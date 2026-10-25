# PE Version Resource Strings

The PE resource inventory now reads the `StringFileInfo` portion of bounded
`RT_VERSION` resources in addition to the fixed `VS_FIXEDFILEINFO` versions.
Decoded fields retain their UTF-8 key and value, language ID, code page, and
source spans. The desktop resource table shows common identity fields such as
`FileDescription`, `CompanyName`, `ProductName`, `OriginalFilename`, and
`InternalName`; CLI inspection emits the bounded decoded string rows.

Parsing is limited to 1 MiB per resource and 16 MiB across an image. At most
4,096 string records are retained per resource, and CLI output is capped at
4,096 strings total. Malformed child blocks and resources exceeding the
inspection budget keep the resource inventory and fixed version fields where
available, while marking string-table decoding incomplete. When the shared
image budget is exhausted, later version resources remain inventory-only.
These fields are
metadata read from the file; HexLab does not execute version-resource code or
interpret the values as trusted identity.
