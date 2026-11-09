# bcm4908img known findings

`bootfs-zero-totlen-hang.img`: `bcm4908img bootfs -i <img> ls` (and `bootfs mv`) loops forever.
In `bcm4908img_bootfs_ls()` (`package/utils/bcm4908img/src/bcm4908img.c`) the node walk advances by
`(totlen + 3) & ~3`; a non-DIRENT JFFS2 node with `totlen` 0..3 never advances `offset`, so the same
node is re-read endlessly. Reproduce: `timeout 10 bcm4908img bootfs -i bootfs-zero-totlen-hang.img ls` exits 124.
The image has a valid trailing CRC32, so it passes the image check. Not in `testsuite/` so seed runs stay clean.
