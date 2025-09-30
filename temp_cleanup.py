from pathlib import Path

path = Path(r"c:/Users/WaelAshrafIGRCSQUARE/Desktop/EyeGuard/eyeguard/frontend/src/pages/PcapAnalysisPage.jsx")
text = path.read_text()
start_marker = "        {showJobStatus && ("
start = text.find(start_marker)
if start == -1:
    raise SystemExit('showJobStatus block not found for cleanup')
# locate end of new block we inserted (the first occurrence of '\n        {uploadError' after the showJobStatus block)
search_start = text.find("        {uploadError", start)
if search_start == -1:
    raise SystemExit('uploadError block not found')
# but ensure we only remove the text between the end of our new block and uploadError
# find the end of the new block by locating the first '\n        {uploadError'
new_block_end = text.find("\n        {uploadError", start)
if new_block_end == -1:
    raise SystemExit('could not locate uploadError newline')
# remove content between end of new block and uploadError block
text = text[:new_block_end] + text[new_block_end:]
# but we still have duplicate block because new_block_end currently points at newline preceding uploadError; we just need to ensure there's only one occurrence
# Now remove any repeated '            {showSelfCheck && (' after uploadError block? We'll do explicit removal to be safe.
# Replace double occurrence of showSelfCheck block after uploadError by ensuring only our new block exists
while '\n            {showSelfCheck && (' in text[new_block_end: text.find('        {uploadError', new_block_end)]:
    # this should not happen after cleanup
    break
path.write_text(text)
