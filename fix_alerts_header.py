from pathlib import Path
path = Path('src/components/AlertsTable.jsx')
text = path.read_text()
prefix = "// Software-only simulation / demo - no real systems will be contacted or modified.import React, { useContext, useEffect, useMemo, useState } from 'react';"
if text.startswith(prefix):
    replacement = "// Software-only simulation / demo - no real systems will be contacted or modified.\nimport React, { useContext, useEffect, useMemo, useState } from 'react';"
    text = replacement + text[len(prefix):]
    path.write_text(text)
