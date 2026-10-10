# Run from the repo root where contract/ lives. Example: make -C contract check-M2
PY ?= python3
T  := tools
MODS := M1 M2 M3 M4 M5 M6 M7 M8
dir_M1=m1_ingestion
dir_M2=m2_static
dir_M3=m3_dynamic
dir_M4=m4_ioc
dir_M5=m5_detection
dir_M6=m6_response
dir_M7=m7_core
dir_M8=m8_ui_devops

.PHONY: contract-test gate $(addprefix check-,$(MODS)) $(addprefix stub-,$(MODS))

contract-test:                       ## run the contract's own test suite
	$(PY) -m unittest discover -s tests -v

gate:                                ## CI gate: every module's golden outputs must satisfy the contract
	$(PY) $(T)/check_all.py --repo-root .. --require-all

# make check-M2            -> validates ../m2_static/contract_out/*.json and contract_events/*.json
$(addprefix check-,$(MODS)): check-%:
	@for f in ../$(dir_$*)/contract_out/*.json; do [ -e $$f ] || continue; $(PY) $(T)/check_module.py --module $* --file $$f || exit 1; done; \
	for f in ../$(dir_$*)/contract_events/*.json; do [ -e $$f ] || continue; $(PY) $(T)/check_module.py --module $* --event $$f || exit 1; done

# make stub-M2             -> writes contract-valid stub output + event into the module folder
$(addprefix stub-,$(MODS)):  stub-%:
	-$(PY) $(T)/stub_module.py $* --out ../$(dir_$*)/contract_out/stub.json
	-$(PY) $(T)/stub_module.py $* --event --out ../$(dir_$*)/contract_events/stub.json
