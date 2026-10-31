.PHONY: academy-backend
academy-backend:
	MAKELEVEL=0 $(MAKE) -j4 -C build/src/backend all
