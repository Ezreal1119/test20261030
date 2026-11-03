# DT610 Pro authentication verification

Reference implementation for a UROVO DT610 Pro tender check:

Android Keystore device authentication + FIDO2/WebAuthn phishing-resistant user verification + a measured sign-on that includes both.

The app is a technical verification tool. It is not an identity provider and it does not simulate cryptographic success.

## What a passing run shows

On the device that actually ran the test, under the network and relying party used that day:

- The handset created an ECDSA P-256 key inside Android Keystore and the private key was not exportable through the standard Android APIs.
- The backend verified a signature over a single-use random challenge with the enrolled public key.
- Credential Manager completed a WebAuthn ceremony and the backend checked the challenge, RP ID hash, origin, signature, and user-verification flag.
- Both results belonged to the same server transaction. The authenticated screen opens only after that transaction has a session.
- The sign-on duration came from one `SystemClock.elapsedRealtimeNanos()` timer started on the button press and stopped when the home screen was ready.

## What it does not show

- Compatibility with the customer's identity provider, production app, or operational network.
- The customer's production sign-on time. A lab average under 20 seconds is not that claim.
- That a Google Password Manager Passkey is device-bound. Backup eligibility (BE) is reported. BE set means the credential may be synced.
- That a key is hardware-backed merely because it lives in Android Keystore. If attestation does not verify, the report says `Hardware-backed attestation not verified.`
- That a local PIN prompt, by itself, satisfies the customer's enterprise MFA policy.

The PDF states these limits in section 7. Empty sections stay `NOT TESTED`. The report is built from backend rows, not from edited numbers.

## Layout

- `app/` — Kotlin + XML Android app, min SDK 29, target SDK 35.
- `backend/` — FastAPI, SQLite, `webauthn` 3.0.1, and `cryptography`.
- Package name: `com.patrick.test20261030`.

Device signatures are SHA256withECDSA (DER), which is what Android Keystore produces. WebAuthn ES256 signatures on the wire are raw `r||s`; the server converts that form to DER and then calls the WebAuthn library. Origin and RP ID checks are not disabled. TLS hostname and certificate checks are not disabled. Debug builds also trust user-installed CAs so mkcert can be used; release builds trust system CAs only. Cleartext HTTP is rejected by the app.

## 1. Start the backend

On the Mac:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` before any Passkey test:

```text
RP_ID=auth.example.com
ORIGIN=https://auth.example.com
RP_NAME=DT610 Auth Verification
ADMIN_TOKEN=a-long-random-lab-secret
```

`RP_ID` is the bare hostname. `ORIGIN` must be `https://` plus that same hostname. Do not put a port or path in `RP_ID`.

```bash
./run.sh
```

The API listens on `127.0.0.1:8000` only. If `ADMIN_TOKEN` is empty, the first start writes `backend/data/admin_token` and prints it once.

```bash
python -m app.cli show-token
python -m app.cli issue-token
```

Run the verifier suite on the Mac at any time:

```bash
cd backend
source .venv/bin/activate
pytest -q
```

If `python3 -m venv` fails with `UnicodeDecodeError` on this external volume, macOS AppleDouble files are the usual cause. Run `export COPYFILE_DISABLE=1`, delete `.venv`, and create it again.

The Android build directory is `/tmp/dt610-android-build/app`. On this disk, macOS writes `._drawable` beside resource folders and aapt then fails, so the project sends build output to the local temp disk.

## 2. HTTPS and the relying party

WebAuthn and Digital Asset Links need a public HTTPS name. Do not point the app at `http://` and do not install a trust-all network config.

Recommended: a named Cloudflare Tunnel, or another tunnel you control, aimed at `http://127.0.0.1:8000`.

1. Start the backend.
2. Start the tunnel and note the hostname, for example `auth.example.com`.
3. Set `RP_ID` and `ORIGIN` to that hostname, then restart the backend.
4. Set the same hostname in the project `gradle.properties`:

```text
rpHost=auth.example.com
```

5. Rebuild and reinstall the app. The hostname is compiled into the App Link intent filter and into the string the app displays as "Digital Asset Links host in this build".

A quick-tunnel hostname changes every run. Use a stable name before registering a Passkey. A Passkey is bound to the RP ID it was created with.

The tunnel makes the lab API reachable. The admin token is required on every `/api/` call. `/.well-known/assetlinks.json` stays public because Google has to fetch it. Do not put the backend on the open internet without the token, and do not reuse the token outside this lab.

mkcert is an alternative only when the handset can reach the Mac by a real DNS name and the debug build is installed. Install the mkcert CA on the handset. Debug builds trust user CAs and still verify the certificate chain and hostname.

## 3. Digital Asset Links

The backend serves:

`https://<RP_ID>/.well-known/assetlinks.json`

After the app is installed:

1. Enter the backend `https://` URL and the lab admin token. Tap **Save settings**, then **Check backend**.
2. Tap **Show signing certificate** and confirm the SHA-256 fingerprint.
3. Tap **Publish fingerprint to backend**.

That writes the installed app's signing certificate into asset links. For a debug build this is the debug keystore. For a release build it is the key that signed the APK you installed. If Play App Signing is introduced later, publish Play's app-signing certificate instead and reinstall is not enough until that fingerprint is the one Google sees.

Confirm from the Mac:

```bash
curl https://auth.example.com/.well-known/assetlinks.json
```

The document must include:

- `delegate_permission/common.get_login_creds`
- `delegate_permission/common.handle_all_urls`
- package `com.patrick.test20261030`
- the uppercase colon-separated SHA-256 fingerprint

On the handset, after asset links have had a moment to be fetched:

```bash
adb shell pm verify-app-links --re-verify com.patrick.test20261030
adb shell pm get-app-links com.patrick.test20261030
```

The server accepts two origins, and only those:

- `https://<RP_ID>`
- `android:apk-key-hash:` plus the base64url SHA-256 of each published signing certificate

Credential Manager chooses which form to put in `clientDataJSON`. Anything else is rejected.

## 4. Install the app

Open the project in Android Studio, or from the project root with Android Studio's JDK:

```bash
export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
./gradlew :app:assembleDebug
```

The debug APK is written to `/tmp/dt610-android-build/app/outputs/apk/debug/app-debug.apk`. Install that on the DT610 Pro. The handset needs a network path to the HTTPS origin and a Passkey provider. The earlier Chrome test showed Google Password Manager is available on this device.

## 5. Run the verification

Do these in order on the handset. Have the device PIN ready. The complete-authentication timer includes the PIN prompt.

1. **Issue enrollment token.** This is the administrative enrollment step. A client without a fresh token cannot register or replace a public key.
2. **Generate Device Key.** If the backend is reachable, the key is generated with a server attestation challenge. Replacing an existing key asks for confirmation and does not by itself change the server record.
3. **Inspect Key Security.** Read the algorithm, alias, fingerprint, KeyInfo security level (`SOFTWARE`, `TRUSTED_ENVIRONMENT`, or `STRONGBOX`), whether user authentication is required, and whether the private key is exportable. This screen does not mark hardware attestation verified.
4. **Register Device.** Sends the public key and certificate chain. Enrollment tokens are single-use. If a registration id is already saved, this call is an authorized replacement, not a silent overwrite.
5. **Test Device Authentication.** One standalone challenge-response. It does not create a session.
6. **Register Passkey.** The system sheet must appear. The backend rejects the response unless user verification was performed.
7. **Authenticate with Passkey.** Standalone WebAuthn. It does not create a session. Read BE and BS with **View Credential Properties**.
8. **Run Complete Authentication.** Device signature, then Passkey with PIN or biometric, then session confirmation, then the home screen. The duration breakdown is on that screen.
9. Repeat step 8 until at least 10 successful journeys are stored if the timing claim needs a sample of that size. **View Authentication History** shows minimum, maximum, average, P95 when there are at least 10 corroborated attempts, success rate, and how many attempts exceeded 20 seconds.
10. **Run Negative Tests.**
11. **Export JSON Report** and **Export PDF Report**. Files are written to `Downloads/DT610Auth` and a share sheet opens.

The 20 second target is `<= 20000 ms` on the single monotonic timer. PASS on the home screen means that journey met the target and both factors produced a session. It does not mark the whole requirement compliant.

Section 7 marks sign-on time `VERIFIED` only when at least 10 corroborated successes exist, every corroborated attempt is within 20 seconds, there are no failures in that set, and no device timer disagrees with the server window by more than 15 seconds. Fewer successes, or a clean but small sample, stay `PARTIALLY VERIFIED`. Any attempt over 20 seconds is `NOT VERIFIED` for that item. The average is displayed and is not the criterion.

Customer enterprise IdP integration stays `NOT VERIFIED`.

## 6. Negative tests

Device-side, against the live API, using this handset's Android Keystore key:

| Check | Expected |
| --- | --- |
| Valid device signature | accepted |
| Modified signature | rejected |
| Replayed challenge | rejected |
| Unknown device | rejected |
| Signature from a different P-256 key | rejected |

Expired challenges, wrong WebAuthn challenge, wrong origin, wrong RP ID, missing UV, and the two session-binding cases run in the server suite. That suite calls the same verification functions as the API. It uses real ES256 signatures from an in-process authenticator. It does not return canned pass/fail text. Those rows are labeled as verifier checks, not DT610 measurements.

A session is created only inside the integrated transaction, and only after both factors succeed for that transaction id.

## 7. Attestation

Generate the key while the backend is reachable so `setAttestationChallenge` receives the server nonce. Register Device uploads the certificate chain.

The backend checks chain signatures, a pinned root in `backend/app/resources/attestation_roots.pem`, the challenge, the leaf public key, and the keymaster security level inside the attestation extension. Place the Google hardware attestation roots from the [Android key attestation documentation](https://developer.android.com/privacy-and-security/security-key-attestation) in that PEM file, one certificate after another.

If the file is missing, the chain does not end at a pinned root, the challenge differs, or the keymaster level is software, the stored status is `Hardware-backed attestation not verified.` KeyInfo's own security level is still shown and is labeled as reported by the device.

## 8. Evidence file

Suggested report title, also used by the exporter:

`UROVO DT610 Pro – Device-Bound Authentication and Phishing-Resistant MFA Verification Report`

Sections: test environment, device authentication, WebAuthn, integrated authentication, negative tests, performance, and the six-part compliance assessment (`VERIFIED`, `PARTIALLY VERIFIED`, `NOT VERIFIED`).

Device-measured durations are stored only when they match the server transaction. A client cannot post a passing time for a transaction that did not complete. The server also stores the time from transaction creation to session creation so a large disagreement is visible.

## Troubleshooting

- **Admin token was rejected.** The token in the app must match `ADMIN_TOKEN` or `backend/data/admin_token`.
- **RP ID does not match this build.** `gradle.properties` `rpHost`, backend `RP_ID`, and the tunnel hostname must be identical. Rebuild after changing `rpHost`.
- **Passkey sheet never appears.** Fingerprint not published, asset links not reachable at the RP origin, or the Passkey provider is unavailable.
- **Origin rejected after a successful sheet.** Publish the fingerprint of the certificate that actually signed the installed APK, then register the Passkey again.
- **Enrollment token invalid.** Tokens are single-use and last 24 hours. Issue another one.
- **Home screen did not open.** The session GET failed or the transaction did not complete. The app will not open that screen on a local guess.
