# User-flow implementation plan

1. Replace device-approval requests with one-time device-linking OTPs: an active device creates one; a new device redeems it with a new signing key and proof of possession.
2. Change email recovery into email fallback: verify the OTP, sign in or add only the current device, and leave every other device unchanged.
3. Add editable, recognizable default device labels. Show active devices first and muted inactive devices second; support current-device and remote-device logout.
4. Make **Transfer to this device** create the authenticated WebRTC/TURN connection first, then open the sender's file picker.
5. Forward signed file name, size, and type only to the selected recipient. Do not store this metadata. The recipient accepts or declines before any file bytes are sent.
6. Show **Successful send!** and **Successful receive!** on verified completion, then return both devices to their default state after three seconds.
7. Replace affected API, database, frontend, protocol, and browser tests together; remove the old pairing approval path rather than keeping both flows.

## Required flow

1. New user enters email and requests for email OTP
2. User enters email OTP. at this point, the user now has a registered account.
3. The registering device gets to choose its own name, but by default it should take some identifier tied to the device (e.g. Samsung A55 5g or something along those lines, preferably something tied to the device's identity and easily recognizable). Users should also be able to modify the device name.
4. To link a new device to the account, any of the user's active devices can generate an OTP.
5. The user can enter that OTP into their new device to link it to the account. There should be no need for emails and passwords here.
6. There should be a display of active devices, and greyed out inactive devices, listed below the active ones. To initiate a transfer, click "Transfer to this device". It should automatically establish the peer-to-peer/TURN connection, then bring up the file picker automatically after loading.
7. The target device sees a button to accept the file. There should be information regarding file name, size, type displayed on the target device before it accepts.
8. After accepting, display "Successful send!" on the sender, and "Successful receive!" on the receiver. After 3 seconds they should revert back to default state
9. Each device should be able to log themselves out, and have the option to log other devices out as well.
10. In the event that the user is completely logged out from all devices, there should be a "Use email instead?" button (similar to password recovery) that sends the user an OTP via email to log in to their own account on that specific device. All other existing devices should remain unchanged.
