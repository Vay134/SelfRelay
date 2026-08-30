# User flow

## Account and device access

1. A new user enters an email address and requests an email OTP.
2. The user enters the OTP. The verified email creates or opens the account.
3. The registering device receives an editable name. The app pre-fills a recognizable best-effort browser/device description, such as a browser-provided phone model when available; it falls back to a neutral label rather than collecting a hardware fingerprint.
4. An active device can generate a one-time device-linking OTP.
5. A new device generates its local key, enters that OTP, chooses its label, and joins the account. This route uses neither email nor a password.
6. The device screen lists active devices first. Logged-out devices follow in a visually muted inactive section. Each device can be renamed. A user can log out the current device or another device.
7. If every device is logged out, the sign-in screen offers **Use email instead?**. A verified email OTP signs the current device in or adds it to the existing account without changing any other device.

## File transfer

1. The user selects **Transfer to this device** beside an active destination device.
2. The app starts the direct WebRTC connection, using TURN when required, and opens the sender's file picker as soon as the connection is ready.
3. After the sender selects one file, the recipient sees its name, size, and type plus an **Accept file** button. Metadata is shown as plain text and is never stored by the service.
4. The recipient accepts or declines. Acceptance starts encrypted file transfer; decline sends no file bytes.
5. On completion, the sender sees **Successful send!** and the receiver sees **Successful receive!**. Each message returns to the default device screen after three seconds.

## Interaction constraints

- A transfer can target only an active device. Inactive devices remain visible but have no transfer action.
- The sender must choose a file before the recipient can be shown its metadata. This is required for the recipient to make an informed acceptance decision.
- File metadata is not a safety verdict. The UI must not automatically preview or open the received file.
- Both devices must remain open and online for the duration of the transfer.
