"""Usage: hexlab_python search.py existing.hxproj '48 8B ?? C3'"""
import sys
import hexlab

if len(sys.argv) != 3:
    raise SystemExit("usage: hexlab_python search.py project.hxproj '48 8B ?? C3'")

with hexlab.Project.open(sys.argv[1]) as project:
    cursor = None
    while True:
        page = project.search_bytes(sys.argv[2], cursor=cursor, max_results=256)
        for match in page.matches:
            print(match["address"] or match["offset"], "size:", match["size"],
                  "file ranges:", match["file_ranges"])
        if page.complete:
            if not page.source_complete:
                print("warning:", page.reason)
            break
        cursor = page.next
