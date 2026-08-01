# 519 Tech Intake Recorder Releases

This public repository contains signed, notarized installers and the automatic-update feed for **519 Tech Intake Recorder**.

The application source code is maintained in a separate private repository. No source code, customer recordings, transcripts, API keys, certificates, or signing keys are stored here.

## Download

Open [Releases](../../releases/latest) and download the latest `.dmg`. Open the installer and drag **519 Tech Intake Recorder** to **Applications**.

Every published installer is expected to be:

- signed with 519 Tech's Apple Developer ID certificate;
- notarized by Apple and stapled;
- signed for automatic-update verification with Sparkle EdDSA.

## Release verification

The release workflow requires two non-secret repository variables:

- `APPLE_TEAM_ID`: the 10-character Team ID expected in the Developer ID signature.
- `SPARKLE_PUBLIC_ED_KEY`: the canonical Base64 Ed25519 public key embedded in the app.

Only increasing `vMAJOR.MINOR.PATCH` tags on `main` are accepted. Before creating a release, the workflow verifies the Developer ID signature, notarization ticket, bundle metadata, required data-protection-Keychain provisioning profile, signed Sparkle feed, and signed DMG enclosure. It creates a draft containing exactly the DMG and appcast, verifies the uploaded bytes, publishes, then downloads and verifies the published assets again.

Repository administrators should also enable GitHub's immutable-releases setting and protect `main` plus `v*` tags so only the dedicated private-repository release automation can update them.
