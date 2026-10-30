# File offset aliases

`Image::to_address` maps an initialized file offset only when exactly one
virtual address backs it. It returns an ambiguity error when multiple image
segments reuse the same source bytes.

`Image::to_addresses` exposes all such aliases in stable address-space and
offset order. It returns an empty list when the offset has no initialized
virtual backing. Zero-filled segment tails are not included because they have
no source file byte. This query reports mapping only; it does not check segment
read, write, or execute permissions.
