import pathlib
import subprocess
import sys
import tempfile

runner = sys.argv[1]
with tempfile.TemporaryDirectory(prefix="hexlab-console-") as temporary:
    script = pathlib.Path(temporary) / "failure.py"
    script.write_text("import hexlab\nraise RuntimeError('intentional console failure')\n")
    result = subprocess.run([runner, str(script)], capture_output=True, text=True, timeout=30)
    assert result.returncode != 0 and "Traceback" in result.stderr and "intentional console failure" in result.stderr
    missing = subprocess.run([runner, str(script) + ".missing"], capture_output=True, text=True, timeout=30)
    assert missing.returncode != 0
    unicode_script = pathlib.Path(temporary) / "unicode-\u03bb.py"
    (pathlib.Path(temporary) / "local_helper.py").write_text("VALUE = 37\n")
    unicode_script.write_text("import sys, local_helper\nassert sys.argv[1] == '\\u03bb'\nassert local_helper.VALUE == 37\n")
    unicode_run = subprocess.run([runner, str(unicode_script), "\u03bb"], capture_output=True, text=True, timeout=30)
    assert unicode_run.returncode == 0, unicode_run.stderr
    repl = subprocess.run([runner], input="import hexlab; print('console-api', hexlab.API_VERSION)\n", capture_output=True, text=True, timeout=30)
    assert repl.returncode == 0 and "console-api 1" in repl.stdout
    print("Python console: traceback, missing script and interactive input contracts passed")
