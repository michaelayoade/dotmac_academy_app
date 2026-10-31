.PHONY: academy-backend
academy-backend:
	MAKELEVEL=0 $(MAKE) -C build/src/backend generated-headers
	MAKELEVEL=0 $(MAKE) -j4 -C build/src/backend all
