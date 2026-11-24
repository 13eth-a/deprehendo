#!/bin/bash
# deprehendo demo voiceover: records one clip per scene with macOS `say`.
# Writes only into the folder this script is in. Safe to delete afterwards;
# don't commit it.
#   bash demo-voiceover/record.sh                    # best installed voice
#   VOICE="Zoe (Premium)" bash demo-voiceover/record.sh   # pick one yourself
#   RATE=160 bash demo-voiceover/record.sh            # slower (default 168 wpm)
set -euo pipefail
cd "$(dirname "$0")"

RATE="${RATE:-168}"
installed="$(say -v '?' | sed -E 's/  +[a-z]{2}_[A-Z]{2}.*$//; s/[[:space:]]+$//')"
if [ -z "${VOICE:-}" ]; then
  for v in "Ava (Premium)" "Zoe (Premium)" "Evan (Premium)" "Nathan (Premium)" "Noelle (Premium)" \
           "Ava (Enhanced)" "Zoe (Enhanced)" "Evan (Enhanced)" "Samantha (Enhanced)" "Samantha"; do
    if printf '%s\n' "$installed" | grep -qxF "$v"; then VOICE="$v"; break; fi
  done
fi
if [ -z "${VOICE:-}" ] || ! printf '%s\n' "$installed" | grep -qxF "$VOICE"; then
  echo "No suitable voice found. Installed English voices:"; say -v '?' | grep -E 'en_(US|GB)'; exit 1
fi
echo "voice: $VOICE   rate: $RATE"
case "$VOICE" in *Premium*) ;; *) echo "tip: a Premium voice sounds far more natural. Add one in System Settings > Accessibility > Spoken Content > System Voice > Manage Voices (e.g. Ava or Zoe, Premium), then run this again.";; esac

# "deprehendo" is spelled out phonetically so the voice says deh-preh-HEN-doh.
lines=(
  "01|Meet, deh-preh-hendo."
  "02|When a self-hosted GitHub Actions runner dies in the middle of a job, deh-preh-hendo tells you why."
  "03|Getting started takes three commands: build the agent, log in, and upload."
  "04|Every incident your organization uploads lands here, newest first."
  "05|Open one, and the diagnosis is right at the top. Here, an out-of-memory kill, with high confidence."
  "06|Click any piece of evidence, to see its source, its timing, and the raw value, exactly as recorded."
  "07|The causal chain and timeline show what was observed directly, and what was inferred."
  "08|And when nothing matches, it says so, and shows what GitHub itself reported."
  "09|Light or dark. Compact or comfortable. In your own time zone."
  "10|deh-preh-hendo. Every conclusion, inspectable."
)
for entry in "${lines[@]}"; do
  n="${entry%%|*}"; text="${entry#*|}"
  say -v "$VOICE" -r "$RATE" -o "vo-$n.aiff" "$text"
  printf '  vo-%s.aiff  %s\n' "$n" "$text"
done
printf '%s\n%s\n' "$VOICE" "$RATE" > voice.txt
echo "done: 10 clips in $(pwd)"
