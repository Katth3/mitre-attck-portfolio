# ATT&CK Navigator Layers

Visual coverage heatmaps showing TTP mapping for adversary groups
and detection rule coverage, built with MITRE ATT&CK Navigator.

## How to view these layers

1. Go to https://mitre-attack.github.io/attack-navigator
2. Click **Open Existing Layer** → **From File**
3. Select any `.json` file from this folder

## Layers index

| File | Description | Color |
|------|-------------|-------|
| APT29-coverage.json | APT29 / Cozy Bear full TTP map | Red |
| Lazarus-coverage.json | Lazarus Group full TTP map | Orange |
| detection-rules-coverage.json | Techniques covered by rules in 02-detection-rules | Green |

## Detection coverage layer

`detection-rules-coverage.json` is manually maintained — updated every time
a new Sigma rule is added to the repository. Green = detected, Yellow = partial
coverage, empty = gap.

## Screenshots

### APT29 Coverage
![APT29](../assets/navigator-apt29.png)

### Lazarus Group Coverage
![Lazarus](../assets/navigator-lazarus.png)
