# Project Annotation Batch C++ plugin

This standalone analysis provider opens the selected saved project for editing,
reads its current edit revision, pages the first recovered function, and applies
a function rename and bookmark as one atomic `ProjectClient::annotation_batch`
operation. If another edit changes the revision between the summary read and
the batch, the host rejects the whole operation. A successful operation is one
undoable history step. The provider requires `project.edits` v1.6.

Build and install against a HexLab installation with the matching native SDK:

```sh
cmake -S examples/plugins/project-annotation-batch-cpp -B build/project-annotation-batch-plugin \
  -DCMAKE_PREFIX_PATH=/path/to/hexlab-install
cmake --build build/project-annotation-batch-plugin
cmake --install build/project-annotation-batch-plugin --prefix /path/to/plugin-install
```

Load the module, then run **Project Annotation Batch** on a saved, analyzed
project. It intentionally edits that project; undo once to revert the rename
and bookmark together. It reports failure if no function is available or the
project revision became stale.
