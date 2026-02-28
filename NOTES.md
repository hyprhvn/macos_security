# Notes

Custom notes for HyperHaven UG (haftungsbeschränkt).

A security baseline for Enkime GmbH and based on the CIS Level II baseline, has been generated using the following command:

```bash
./scripts/generate_baseline.py -t -k cis_lvl2
```

The generated baseline can be found in `build/baselines/enkime.yaml`, with custom rules, generated in `custom/rules`.

The resulting configuration profile and compliance script can be generated as follows:

```bash
./scripts/generate_guidance.py -Psx -p build/baselines/enkime.yaml
```

They can then be found in `build/enkime`.
