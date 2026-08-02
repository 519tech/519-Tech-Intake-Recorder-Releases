# 519 Tech Intake Recorder Releases

This public repository contains binary installers and the automatic-update feed for **519 Tech Intake Recorder**. Production installers are Developer ID signed and notarized; explicitly labelled internal support builds are ad-hoc signed and not notarized.

The application source code is maintained in a separate private repository. No source code, customer recordings, transcripts, API keys, certificates, or signing keys are stored here.

## Download

Open [Releases](../../releases/latest) and download the latest `519-Tech-Intake-Recorder-VERSION.dmg`. Open the installer and drag **519 Tech Intake Recorder** to **Applications**.

Every production installer is expected to be:

- signed with 519 Tech's Apple Developer ID certificate;
- notarized by Apple and stapled;
- signed for automatic-update verification with Sparkle EdDSA.

An `internal-v*` installer is a temporary staff build. Its DMG and complete app
bundle are authenticated by the signed Sparkle feed, but macOS may require manual
approval on first launch because it has no Developer ID or notarization ticket.

## Internal build verification

The `internal-vMAJOR.MINOR.PATCH` tag path is reserved for support-only builds. The
`Verify Internal Installer Release` workflow validates a mirrored DMG and signed
appcast with read-only permissions, hands off only the verified files, then uses a
separate least-privilege job to publish exactly those two assets as the Latest
release. An ordinary push to `main` cannot publish an installer; only a validated
internal release tag activates this path.

The internal lane closes permanently as soon as a production `vMAJOR.MINOR.PATCH`
release is published. The verifier also refuses to replace a Latest release outside
the bootstrap or internal lanes.

An internal tagged commit must be on `main`, have exactly one parent, and change only:

- `downloads/internal-vVERSION/519-Tech-Intake-Recorder-VERSION.dmg`
- `latest/appcast.xml`

The verifier requires a structurally valid DMG containing only the app and the
Applications link. The app and all Sparkle helpers must be ad-hoc signed with no Team
Identifier, certificate authority, production provisioning profile, or production
entitlements. Bundle versioning, the update-feed URL and public key, `LSUIElement`,
and `SUInternalBuild` are checked against the tag and repository configuration.

Both the whole appcast and every exact DMG enclosure must have valid Ed25519
signatures. Version `0.1.2` has exactly one default-channel item so installed `0.1.1`
builds can cross onto the internal channel. Every later internal appcast has exactly
two items: the newest `internal`-channel update first, followed by the unchanged
`0.1.2` default-channel bridge. The verifier checks the retained bridge against both
its tagged Git blob and downloaded GitHub release asset, derives its build number from
the mounted bridge app, and authenticates both DMG enclosures. This prevents a `0.1.1`
installation that missed the original bridge release from being stranded.

The public repository stores only the public verification key; private Sparkle keys
remain in the private source repository.

Publishing an ad-hoc internal build makes its compiled DMG and signed appcast publicly
downloadable. The private source workflow therefore fails closed unless its owner has
explicitly enabled that disclosure before creating the mirrored tag.

## Release verification

The release workflow requires two non-secret repository variables:

- `APPLE_TEAM_ID`: the 10-character Team ID expected in the Developer ID signature.
- `SPARKLE_PUBLIC_ED_KEY`: `gPDlaoHU2zbAMYp3KKD5x0su3OOp2WNPAlj0Az7x+oc=`, the trust root already embedded in installed apps.

Only increasing `vMAJOR.MINOR.PATCH` tags on `main` are accepted. Before creating a release, the workflow verifies the Developer ID signature, notarization ticket, bundle metadata, required data-protection-Keychain provisioning profile, signed Sparkle feed, and signed DMG enclosure. It creates a draft containing exactly the DMG and appcast, verifies the uploaded bytes, publishes, then downloads and verifies the published assets again.

Repository administrators should also enable GitHub's immutable-releases setting and protect `main` plus `v*` tags so only the dedicated private-repository release automation can update them.
