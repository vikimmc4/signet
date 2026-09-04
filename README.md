# Signet

A single-file PDF e-signing app. Prepare a PDF, place signature / date / text
fields for each recipient, and email a signing request that opens on any
device — phone included.

`index.html` is the whole application. There is nothing to build or install.

## Why signing requests are data files, not web pages

The obvious design is to email a self-contained HTML page that the signer just
opens. That works on desktop and fails on iPhone: since iOS 13, Apple Mail and
the Gmail app preview HTML attachments through Quick Look / WebView with
**JavaScript disabled**, so the page arrives inert.

So the app and the document travel separately:

- **The app** is published once at a stable `https://` address. It holds no
  documents — it is the blank tool.
- **The document** travels as a small `.signet.json` file attached to your
  email. The signer opens the published app and loads that file.

Your PDF therefore never touches the host, and there is no per-document upload,
no database, and no account for anyone.

## Publishing it

Any static host works. With GitHub Pages:

1. Create a new public repository (for example `signet`).
2. Push this folder to it.
3. Settings → Pages → Source: `Deploy from a branch`, branch `main`, folder `/`.

The app reads its own address from `location`, so once it is served over
`https://` the signer instructions it writes into your Gmail message point at
the right place automatically. To override that — a custom domain, say — use
*Change this address* in the send dialog.

## Using it

**To send something for signature**

1. Drop a PDF in.
2. Add the recipient's name and email, then place their fields on the page.
   Each person gets their own colour.
3. *Continue to send* → fill any fields of your own → *Build the signing
   request*.
4. Gmail opens with the message written. Attach the `.signet.json` file and
   send.

**To sign something someone sent you**

1. Save the attached `.signet.json` file.
2. Open the published app and choose *I was asked to sign something*.
3. Tap the highlighted boxes, then *Finish*. On a phone the signed PDF goes
   straight to the share sheet; on desktop it downloads.

Every finished PDF gets a **Certificate of Completion** page listing the
envelope ID, each signer, their email, and the timestamp and browser they
signed from.

**Drafts.** *Save draft* writes a `.signet.json` you can reopen later from
*Resume a saved draft* — the PDF and all placed fields come back with it.

## Requirements

Needs an internet connection on load, for `pdf.js` and `pdf-lib` from a CDN.
If they cannot be reached the app says so plainly rather than failing on the
first click. Everything else — rendering, signing, PDF generation — happens
locally in the browser.

## Limits worth knowing

- Signatures are flattened images stamped into the PDF. This is not a
  cryptographic digital signature (no PKI, no tamper detection); it is the same
  class of evidence as a scanned wet signature plus an audit record.
- Signing is sequential and manual: for multiple signers you send each request
  in turn.
- Nothing is tracked server-side, so the app cannot tell you whether a signer
  has opened their request.
