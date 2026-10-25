import os
import json
import pathlib
import sys
import tempfile
import threading

import hexlab

assert hexlab.API_VERSION == 1
assert sys.argv[1:] == ["sentinel"]
with hexlab.DebuggerSession.native() as debugger:
    assert debugger.state == hexlab.DebuggerSession.IDLE
    try:
        debugger.wait_event(timeout_ms=0)
    except hexlab.Error:
        pass
    else:
        raise AssertionError("idle debugger session returned an event")
try:
    debugger.state
except ValueError:
    pass
else:
    raise AssertionError("closed debugger session remained usable")
with tempfile.TemporaryDirectory(prefix="hexlab-python-") as temporary:
    root = pathlib.Path(temporary)
    source = root / "original.bin"
    source.write_bytes(b"\x90\xc3batch artifact string\0")
    path = root / "unicode-\u03bb.hxproj"
    with hexlab.Project.create_raw(path, source, mode="x86-64", base=0x1000, space=7) as project:
        initial = project.snapshot()
        word = hexlab.TypeSpec.integer("u32", 4, alignment=4)
        node = hexlab.TypeSpec.structure("Node", [
            ("value", word, 0),
            ("next", hexlab.TypeSpec.pointer(hexlab.TypeSpec.named_reference("Node"), 8, alignment=8), 8),
        ], size=16, alignment=8)
        node_id = project.define_type("Node", node)
        project.assign_type(hexlab.Address(7, 0x1000), node_id)
        typed = project.snapshot()
        assert typed["types"] == [{"id": node_id, "name": "Node", "type": node}]
        assert typed["type_assignments"] == [{"location": hexlab.Address(7, 0x1000), "type_id": node_id}]
        project.undo()
        assert project.snapshot()["type_assignments"] == []
        project.redo()
        assert project.snapshot()["type_assignments"] == typed["type_assignments"]
        revised_node = hexlab.TypeSpec.structure("Node", [
            ("value", word, 0),
            ("next", hexlab.TypeSpec.pointer(hexlab.TypeSpec.named_reference("Node"), 8, alignment=8), 8),
            ("flags", hexlab.TypeSpec.integer("u32", 4, alignment=4), 16),
        ], size=24, alignment=8)
        project.update_type(node_id, "Node", revised_node)
        assert project.snapshot()["types"][0]["type"] == revised_node
        project.undo()
        assert project.snapshot()["types"][0]["type"] == node
        project.redo()
        assert project.snapshot()["types"][0]["type"] == revised_node
        project.assign_type(hexlab.Address(7, 0x1000), node_id, remove=True)
        assert project.snapshot()["type_assignments"] == []
        project.undo()
        assert project.snapshot()["type_assignments"] == typed["type_assignments"]
        circular_a = hexlab.TypeSpec.structure("CircularA", [
            ("b", hexlab.TypeSpec.pointer(hexlab.TypeSpec.named_reference("CircularB"), 8, alignment=8), 0),
        ], size=8, alignment=8)
        circular_b = hexlab.TypeSpec.structure("CircularB", [
            ("a", hexlab.TypeSpec.pointer(hexlab.TypeSpec.named_reference("CircularA"), 8, alignment=8), 0),
        ], size=8, alignment=8)
        imported = project.import_types(
            {"CircularA": circular_a, "CircularB": circular_b},
            [(hexlab.Address(7, 0x1001), "CircularA")], group=29)
        assert {row["name"]: row["type"] for row in imported["types"]}["CircularA"] == circular_a
        circular_a_id = next(row["id"] for row in imported["types"] if row["name"] == "CircularA")
        assert imported["type_assignments"][-1] == {
            "location": hexlab.Address(7, 0x1001), "type_id": circular_a_id}
        project.undo()
        assert not any(row["name"].startswith("Circular") for row in project.snapshot()["types"])
        assert project.snapshot()["type_assignments"] == typed["type_assignments"]
        project.redo()
        assert any(row["name"] == "CircularB" for row in project.snapshot()["types"])
        revised_circular_a = hexlab.TypeSpec.structure("CircularA", [
            ("next", hexlab.TypeSpec.pointer(hexlab.TypeSpec.named_reference("CircularB"), 8, alignment=8), 0),
        ], size=8, alignment=8)
        updated_graph = project.import_types({"CircularA": revised_circular_a})
        assert next(row["id"] for row in updated_graph["types"] if row["name"] == "CircularA") == circular_a_id
        assert next(row["type"] for row in updated_graph["types"] if row["name"] == "CircularA") == revised_circular_a
        project.undo()
        assert next(row["type"] for row in project.snapshot()["types"] if row["name"] == "CircularA") == circular_a
        project.undo()
        assert not any(row["name"].startswith("Circular") for row in project.snapshot()["types"])
        project.redo()
        project.undo()
        vector_spec = hexlab.TypeSpec.vector(word, 4, alignment=16)
        vector_id = project.define_type("Vec4i", vector_spec)
        assert vector_id > 0
        assert next(row["type"] for row in project.snapshot()["types"] if row["name"] == "Vec4i") == vector_spec
        project.undo()
        assert not any(row["name"] == "Vec4i" for row in project.snapshot()["types"])
        try:
            project.import_types(
                {"NoPartialType": hexlab.TypeSpec.integer("u16", 2)},
                [(hexlab.Address(7, 0x1002), "MissingType")])
        except ValueError:
            pass
        else:
            raise AssertionError("portable type import accepted an unresolved assignment")
        assert not any(row["name"] == "NoPartialType" for row in project.snapshot()["types"])
        try:
            project.import_types({
                "Unresolved": hexlab.TypeSpec.pointer(
                    hexlab.TypeSpec.named_reference("MissingType"), 8, alignment=8)})
        except ValueError as error:
            assert "MissingType" in str(error)
        else:
            raise AssertionError("portable type import accepted a dangling named reference")
        assert initial["entries"] == [hexlab.Address(7, 0x1000)]
        assert len(project.functions()) == 1
        assert project.function_at(hexlab.Address(7, 0x1001))["entry"] == hexlab.Address(7, 0x1000)
        assert project.function_at(hexlab.Address(7, 0x1002)) is None
        pseudocode = project.decompile(hexlab.Address(7, 0x1001))
        assert pseudocode.entry == hexlab.Address(7, 0x1000)
        assert pseudocode.complete and pseudocode.text and isinstance(pseudocode.diagnostics, tuple)
        try:
            project.decompile(hexlab.Address(7, 0x1002))
        except hexlab.Error:
            pass
        else:
            raise AssertionError("decompile accepted an address outside a recovered function")
        assert [row["text"] for row in project.instructions()] == ["nop", "ret"]
        segment = project.segments()[0]
        assert segment == {"name": "raw", "begin": hexlab.Address(7, 0x1000), "size": len(source.read_bytes()),
                          "file_begin": hexlab.FileOffset(0), "file_size": len(source.read_bytes()),
                          "readable": True, "writable": False, "executable": True}
        report_path = root / "analysis.json"
        report = project.export_analysis_json(report_path)
        decoded = json.loads(report_path.read_text(encoding="utf-8"))
        assert report["function_count"] == 1
        assert decoded["functions"][0]["entry"] == {"space": 7, "offset": 0x1000}
        assert decoded["instructions"][0]["bytes_hex"] == "90"
        assert decoded["segments"][0]["begin"] == {"space": 7, "offset": 0x1000}
        assert any(row["preview"] == "batch artifact string" for row in decoded["strings"])
        try:
            project.export_analysis_json(report_path)
        except FileExistsError:
            pass
        else:
            raise AssertionError("analysis export replaced existing output")
        assert project.read(hexlab.Address(7, 0x1000), 2) == source.read_bytes()[:2]
        first = project.search_bytes("??", max_results=1)
        assert len(first.matches) == 1 and first.matches[0]["offset"] == hexlab.FileOffset(0)
        assert not first.complete and first.next is not None
        second = project.search_bytes("??", cursor=first.next, max_results=1)
        assert len(second.matches) == 1 and second.matches[0]["offset"] == hexlab.FileOffset(1)
        assert second.matches[0]["address"] == hexlab.Address(7, 0x1001)
        text_hits = project.search_text("batch", encoding="ascii")
        assert text_hits.complete and text_hits.matches[0]["offset"] == hexlab.FileOffset(2)
        project.define_function(hexlab.Address(7, 0x1000))
        project.analyze()
        project.set_function_chunks(hexlab.Address(7, 0x1000), [(hexlab.Address(7, 0x1000), 2)])
        project.analyze()
        project.set_reference(hexlab.FileOffset(0), hexlab.Address(7, 0x1001))
        project.analyze()
        assert project.references(hexlab.FileOffset(0))[0]["target"] == hexlab.Address(7, 0x1001)
        project.rename(hexlab.Address(7, 0x1000), "script_start")
        project.comment(hexlab.FileOffset(0), "script comment", group=17)
        project.bookmark(hexlab.FileOffset(0), "script bookmark", group=17)
        project.undo()
        assert project.snapshot()["bookmarks"] == []
        project.redo()
        try:
            project.patch(hexlab.Address(7, 0x1000), b"\xcc", expected_revision=initial["edit_revision"])
        except hexlab.Error as error:
            assert error.code == 8
        else:
            raise AssertionError("stale edit revision accepted a byte patch")
        project.patch(hexlab.Address(7, 0x1000), b"\xcc", expected_revision=project.snapshot()["edit_revision"])
        try:
            project.search_bytes("??", cursor=second.next, max_results=1)
        except hexlab.Error as error:
            assert error.code == 8
        else:
            raise AssertionError("search cursor survived a source byte revision")
        try:
            project.instructions()
        except hexlab.Error as error:
            assert error.code == 8
        else:
            raise AssertionError("stale instructions returned")
        project.analyze()
        assert project.instructions()[0]["text"] == "int3"
        assert initial["annotations"] == []
        project.export_binary(root / "export.bin")
        assert (root / "export.bin").read_bytes() == b"\xcc\xc3batch artifact string\0"
        project.save_as(root / "copy.hxproj")
        assert project.read(hexlab.FileOffset(0), 0) == b""
        for bad in (lambda: project.read(hexlab.FileOffset(0), 1048577),
                    lambda: project.functions(count=0),
                    lambda: project.instructions(start=-1),
                    lambda: project.read(hexlab.Address(99, 0), 1)):
            try:
                bad()
            except (hexlab.Error, OverflowError, ValueError):
                pass
            else:
                raise AssertionError("invalid request accepted")
        result = []
        def other_thread():
            try:
                project.snapshot()
            except hexlab.Error as error:
                result.append(error.code)
        thread = threading.Thread(target=other_thread)
        thread.start()
        thread.join()
        assert result == [8]  # ErrorCode::conflict
        project.save()
    try:
        project.snapshot()
    except ValueError:
        pass
    else:
        raise AssertionError("closed project remained usable")
    source.unlink()  # reopen uses embedded input
    with hexlab.Project.open(path) as readonly:
        assert readonly.snapshot()["readonly"]
        assert readonly.snapshot()["types"][0]["type"] == revised_node
        assert readonly.snapshot()["type_assignments"] == typed["type_assignments"]
        assert readonly.snapshot()["annotations"][0]["name"] == "script_start"
        try:
            readonly.import_types({"ReadOnlyType": hexlab.TypeSpec.integer("u16", 2)})
        except hexlab.Error as error:
            assert error.code == 9
        else:
            raise AssertionError("readonly project accepted a portable type import")
        try:
            readonly.comment(hexlab.FileOffset(0), "blocked")
        except hexlab.Error as error:
            assert error.code == 9 and "read only" in str(error).lower()
        else:
            raise AssertionError("readonly edit accepted")
    with hexlab.Project.open(path, readonly=False) as writable:
        writable.comment(hexlab.FileOffset(1), "writable reopen")
    try:
        hexlab.Project.open(path, api_version=99)
    except hexlab.Error as error:
        assert error.code == 4
    else:
        raise AssertionError("unknown API version accepted")
    profile = root / "real.profile"
    profile.write_text('hexlab-x86-profile 1\nenvironment real386\na20 enabled\nload 0x10000\nentry 7 0x10\nstack none\ndomains 2\ndomain 7 0x1000 code "one" real\ndomain 9 0x1001 code "two" real\n')
    source.write_bytes(b"\x90" * 16 + b"\xc3")
    with hexlab.Project.create_profile(root / "seg.hxproj", source, profile) as segmented:
        assert segmented.logical(0x1000, 0x10) == hexlab.Address(7, 0x10)
        assert segmented.logical(0x1001, 0) == hexlab.Address(9, 0)
        assert segmented.read(segmented.logical(0x1000, 0x10), 1) == segmented.read(segmented.logical(0x1001, 0), 1)
    immediate_source = root / "immediate.bin"
    immediate_source.write_bytes(b"\xb0\x2a\xc3")
    with hexlab.Project.create_raw(root / "immediate.hxproj", immediate_source, base=0x2000) as immediate:
        hits = immediate.search_immediate("42", width=8)
        assert hits.complete and hits.source_complete and len(hits.matches) == 1
        assert hits.matches[0]["instruction_address"] == hexlab.Address(0, 0x2000)
        assert hits.matches[0]["operand_index"] == 1
    paging_source = root / "paging.bin"
    paging_source.write_bytes(b"\x90" * 300 + b"\xc3streamed string\0")
    with hexlab.Project.create_raw(root / "paging.hxproj", paging_source) as paging:
        streamed = list(paging.iter_instructions(page_size=100))
        assert len(streamed) == 301
        assert streamed[0]["text"] == "nop" and streamed[-1]["text"] == "ret"
        assert len(list(paging.iter_functions(page_size=1))) == 1
        assert len(list(paging.iter_segments(page_size=1))) == 1
        assert any(row["preview"] == "streamed string" for row in paging.iter_strings(page_size=1))
        try:
            list(paging.iter_instructions(page_size=0))
        except ValueError:
            pass
        else:
            raise AssertionError("invalid iterator page size accepted")
        cancel_requested = [False]
        progress_events = []
        def report_progress(stage, completed, total):
            progress_events.append((stage, completed, total))
            if stage == "instructions" and completed >= 100:
                cancel_requested[0] = True
        canceled_report = root / "canceled-analysis.json"
        try:
            paging.export_analysis_json(canceled_report, page_size=100,
                                        cancel=lambda: cancel_requested[0], progress=report_progress)
        except hexlab.AnalysisCancelled:
            pass
        else:
            raise AssertionError("batch export ignored cooperative cancellation")
        assert not canceled_report.exists()
        assert any(stage == "instructions" for stage, _, _ in progress_events)
        callback_error_report = root / "callback-error-analysis.json"
        def fail_progress(*_):
            raise RuntimeError("progress failed")
        try:
            paging.export_analysis_json(callback_error_report, page_size=100,
                                        progress=fail_progress)
        except RuntimeError as error:
            assert str(error) == "progress failed"
        else:
            raise AssertionError("batch export swallowed a progress callback failure")
        assert not callback_error_report.exists()
        assert not list(root.glob(".canceled-analysis.json.*.tmp"))
        assert not list(root.glob(".callback-error-analysis.json.*.tmp"))
        changed_report = root / "changed-during-export.json"
        changed = [False]
        with hexlab.Project.create_raw(root / "revision-export.hxproj", paging_source) as revision_project:
            def mutate_during_export(stage, completed, total):
                if stage == "instructions" and completed >= 100 and not changed[0]:
                    changed[0] = True
                    revision_project.patch(hexlab.FileOffset(0), b"\xcc")
            try:
                revision_project.export_analysis_json(changed_report, page_size=100,
                                                      progress=mutate_during_export)
            except hexlab.ProjectChangedDuringExport:
                pass
            else:
                raise AssertionError("export published a report assembled across project revisions")
        assert changed[0] and not changed_report.exists()
        assert not list(root.glob(".changed-during-export.json.*.tmp"))
        readonly_batch = hexlab.Project.open(root / "paging.hxproj")
        try:
            readonly_revision = readonly_batch.snapshot()["edit_revision"]
            batch_path = root / "readonly-analysis.json"
            batch = readonly_batch.export_analysis_json(batch_path, page_size=100)
            batch_document = json.loads(batch_path.read_text(encoding="utf-8"))
            assert batch_document["schema_version"] == 1
            assert list(batch_document) == ["schema_version", "api_version", "project", "functions",
                                           "instructions", "segments", "references", "strings"]
            assert batch_document["project"]["readonly"] is True
            assert batch["instruction_count"] == 301
            assert len(batch_document["instructions"]) == 301
            assert readonly_batch.snapshot()["edit_revision"] == readonly_revision
        finally:
            readonly_batch.close()
    long_source = root / "cancel-analysis.bin"
    long_source.write_bytes(b"\x90" * 10000 + b"\xc3")
    with hexlab.Project.create_raw(root / "cancel-analysis.hxproj", long_source) as cancellable:
        token = hexlab.CancellationToken()
        def cancel_native_analysis():
            threading.Event().wait(0.01)
            token.cancel()
        cancel_thread = threading.Thread(target=cancel_native_analysis)
        cancel_thread.start()
        native_cancel_report = root / "native-canceled-analysis.json"
        try:
            cancellable.export_analysis_json(native_cancel_report, page_size=100, cancel=token)
        except hexlab.AnalysisCancelled:
            pass
        else:
            raise AssertionError("native analysis ignored cross-thread cancellation")
        finally:
            cancel_thread.join()
        assert token.cancelled and not native_cancel_report.exists()
    call_source = root / "call.bin"
    call_source.write_bytes(b"\xe8\x01\x00\x00\x00\xc3\xc3")
    with hexlab.Project.create_raw(root / "call.hxproj", call_source, base=0x3000) as calls:
        calls.analyze()
        incoming = calls.incoming_references(hexlab.Address(0, 0x3006), count=1)
        assert incoming.total == 1 and incoming.next is None
        assert incoming.references[0]["source"] == hexlab.Address(0, 0x3000)
        assert incoming.references[0]["kind"] == 0  # ReferenceKind.call
        calls.set_reference(hexlab.FileOffset(5), hexlab.FileOffset(6), kind="data")
        calls.analyze()
        outgoing = calls.all_references(count=1)
        assert outgoing.total == 2 and outgoing.next == 1
        assert outgoing.references[0]["source"] == hexlab.Address(0, 0x3000)
        final_page = calls.all_references(start=outgoing.next, count=1)
        assert len(final_page.references) == 1 and final_page.next is None
        assert final_page.references[0]["source"] == hexlab.FileOffset(5)
        assert len(list(calls.iter_all_references(page_size=1))) == 2
        call_report = root / "call-analysis.json"
        summary = calls.export_analysis_json(call_report)
        call_document = json.loads(call_report.read_text(encoding="utf-8"))
        assert summary["reference_count"] == 2
        assert len(call_document["references"]) == 2
        assert call_document["references"][0]["target"] == {"space": 0, "offset": 0x3006}
print("Python automation: actual project persistence/history/patch/export/readonly/aliases/thread affinity passed")
