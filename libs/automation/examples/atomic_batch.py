from hexlab import Address, Project

project_path = "sample.hxproj"
entry = Address(0, 0x140001000)

with Project.open(project_path, readonly=False) as project:
    before = project.snapshot()
    project.apply_batch(
        [
            ("rename", entry, "entry_main"),
            ("comment", entry, "Imported by a revision-pinned automation batch."),
            ("bookmark", entry, "review", False),
            ("breakpoint", entry, "software", 1, True, False, "", False, "", 0),
        ],
        expected_revision=before["edit_revision"],
    )
    project.save()
