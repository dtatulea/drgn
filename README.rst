This is the temporary drgn fork for my netdev 0x19 talk "Chasing Page Pool Leaks ... with drgns".

What this repo contains:
- Small helper to detect page_pool pages.
- Hack in identify_address to show page_pool pages.
- Scripts used during the talk (based on existing contrib scritpts) under `contrib/pp_leak`:
	- ls_pp_leaks.py: scan all pages for leaked page_pool pages.
	- tcp_sock.py: scan all tcp sockets for SKBs with leaked pages.
	- find.py: find pointer or fuzzy page pointer references in kernel memory.

