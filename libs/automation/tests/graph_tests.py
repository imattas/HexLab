"""Real-project graph navigation catches missing edges, bounds and stale facts."""
import pathlib
import tempfile
import threading
import subprocess
import sys
import hexlab

def rejects(operation, code):
    try:
        operation()
    except hexlab.Error as error:
        assert error.code == code, (error.code, str(error))
    else:
        raise AssertionError("invalid graph query accepted")

with tempfile.TemporaryDirectory(prefix="hexlab-python-graph-") as temporary:
    root = pathlib.Path(temporary)
    source = root / "branch.bin"
    source.write_bytes(bytes.fromhex("85 c0 74 02 90 c3 cc c3"))
    path = root / "branch.hxproj"
    entry = hexlab.Address(9, 0x4000)
    with hexlab.Project.create_raw(path, source, base=0x4000, space=9) as project:
        blocks = list(project.iter_function_blocks(hexlab.Address(9, 0x4002), page_size=1))
        assert [row["begin"] for row in blocks] == [entry, hexlab.Address(9, 0x4004), hexlab.Address(9, 0x4006)]
        assert blocks[0]["instruction_count"] == 2 and blocks[0]["successor_count"] == 2
        block_id = blocks[0]["id"]
        rows = list(project.iter_block_instructions(block_id, page_size=1))
        assert [row["bytes"] for row in rows] == [b"\x85\xc0", b"\x74\x02"]
        assert rows[1]["target"] == hexlab.Address(9, 0x4006)
        edges = list(project.iter_block_successors(block_id, page_size=1))
        assert {(row["kind"], row["target"].offset) for row in edges} == {("conditional_true", 0x4006), ("conditional_false", 0x4004)}
        assert {row["block"] for row in edges} == {row["id"] for row in blocks[1:]}
        assert all(row["source"] == hexlab.Address(9, 0x4002) for row in edges)
        assert blocks[2]["stop"]["reason"] == "trap"
        assert blocks[2]["stop"]["address"] == hexlab.Address(9, 0x4006)
        assert project.block_successors(blocks[2]["id"]) == []
        assert project.function_blocks(entry, start=3, count=1) == []
        assert project.block_instructions(block_id, start=2, count=1) == []
        project.rename(entry, "branch_decision", group=44)
        project.comment(entry, "reviewed conditional", group=44)
        named = project.function_blocks(entry, count=1)[0]
        assert named["presentation"] == {"name": "branch_decision", "comment": "reviewed conditional", "user_name": True, "orphaned": False}
        assert blocks[0]["presentation"]["name"] == "sub_9_4000"
        assert project.presentation(entry) == named["presentation"]
        project.undo()
        assert project.presentation(entry)["comment"] == ""
        project.redo()
        for operation in (lambda: project.function_blocks(entry, count=0),
                          lambda: project.block_instructions(block_id, count=4097),
                          lambda: project.block_successors(block_id, count=0)):
            rejects(operation, 7)
        rejects(lambda: project.function_blocks(hexlab.Address(8, 0x4000)), 2)
        rejects(lambda: project.block_instructions(2**64-1), 2)
        rejects(lambda: project.block_successors(2**64-1), 2)
        failures = []
        def wrong_thread():
            try:
                project.function_blocks(entry)
            except hexlab.Error as error:
                failures.append(error.code)
        worker = threading.Thread(target=wrong_thread)
        worker.start()
        worker.join()
        assert failures == [8]
        project.patch(entry, b"\x90")
        for operation in (lambda: project.function_blocks(entry),
                          lambda: project.block_instructions(block_id),
                          lambda: project.block_successors(block_id)):
            rejects(operation, 8)
        assert project.presentation(entry)["comment"] == "reviewed conditional"
        project.undo()
        project.analyze()
    source.unlink()
    with hexlab.Project.open(path) as project:
        assert project.function_blocks(entry)[0]["presentation"]["name"] == "branch_decision"
        assert project.function_at(entry)["block_count"] == 3
        assert project.snapshot()["readonly"]
    example = subprocess.run([sys.executable, str(pathlib.Path(__file__).parents[1] / "examples" / "function_graph.py"),
                              str(path), "9", "0x4002"], capture_output=True, text=True, timeout=30)
    assert example.returncode == 0, example.stderr
    assert "branch_decision" in example.stdout and "reviewed conditional" in example.stdout
    assert "conditional_true" in example.stdout and "conditional_false" in example.stdout
    assert "trap" in example.stdout
    try:
        project.function_blocks(entry)
    except ValueError:
        pass
    else:
        raise AssertionError("closed project returned graph facts")
print("Python graph: paged CFG navigation, detached presentation, history and reopen passed")
