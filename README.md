# SANE MagicScan driver

## Build instructions

- Simply run `make` with `sane` and its headers installed on your systems.
- Copy the resulting shared library to the SANE backends path (`/usr/lib64/sane/` on Fedora currently).
- Enjoy ✨

## Important Note

Please note that the current kernel (6.16) doesn't implement the good flags for a correct SCSI communication with the device, making the driver basically very slow. A patch is being submitted to the kernel developers but it may take some time to be accepted and deployed.

To patch the kernel yourself, edit the `drivers/usb/storage/unusual_devs.h` file in the source code and add the following lines:

```c
UNUSUAL_DEV(  0x0603, 0x8611, 0x0000, 0xffff,
                "Novatek",
                "NTK96550-based camera",
                USB_SC_SCSI, USB_PR_BULK, NULL,
                US_FL_BULK_IGNORE_TAG )
```

Then build and replace the kernel with your patched one and you're done!