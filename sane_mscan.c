/*
 * sane_mscan - Linux SANE driver for Hyundai (Novatek) Magic Scan
 * Copyright (C) 2025 szf <mael.guerin@murena.io>
 * Copyright (C) 2015 szf <spezifisch@users.noreply.github.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <sane/sane.h>
#include <sane/saneopts.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <scsi/sg.h>
#include <unistd.h>
#include <dirent.h>
#include <stdbool.h>

#define MAX_DEVICES 8
#define SG_IOBUF_LEN 100
#define SG_TIMEOUT 15000 // 15 seconds

static SANE_Device device_list[MAX_DEVICES];
static const SANE_Device *device_ptrs[MAX_DEVICES + 1];
static int device_count = 0;

unsigned char *imgbuf = NULL;
unsigned int offset;
unsigned int global_imgbufsize;

SANE_Option_Descriptor option_count_descriptor;

typedef struct {
    int fd;
} MagicScanHandle;

typedef enum {
    DI_STATUS_NOT_READY,
    DI_STATUS_READY,
    DI_STATUS_OVERSPEED,
    DI_STATUS_INVALIDxx
} DI_Status_t;

typedef enum {
    DI_COLOR_GRAY,
    DI_COLOR_COLOR
} DI_Color_t;

typedef enum {
    DI_DPI_L,
    DI_DPI_M
} DI_DPI_t;

typedef struct {
    DI_Status_t status;
    DI_Color_t color;
    DI_DPI_t dpi;
    int width;
    int height;
    int addr;
} DataInfo_t;

int lowlevelCmd(int fd, unsigned char *cdb_buf, unsigned cdb_len, unsigned char *dxf_buf, unsigned dxf_len)
{
    bool ret = false;
    unsigned char iobuf[SG_IOBUF_LEN] = { 0 };

    struct sg_io_hdr *p = (struct sg_io_hdr *) malloc(sizeof(struct sg_io_hdr));
    if (!p) {
        return ret;
    }
    memset(p, 0, sizeof(struct sg_io_hdr));

    p->interface_id = 'S';
    p->cmdp = cdb_buf;
    p->cmd_len = cdb_len;
    p->flags = SG_FLAG_LUN_INHIBIT;
    p->dxfer_direction = SG_DXFER_FROM_DEV;
    p->dxferp = dxf_buf;
    p->dxfer_len = dxf_len;
    p->sbp = iobuf;
    p->mx_sb_len = SG_IOBUF_LEN;
    p->timeout = SG_TIMEOUT;

    if (ioctl(fd, SG_IO, p) < 0) {
        goto llcmd_fail;
    }

    if (p->resid == 0) {
        ret = true;
    }

llcmd_fail:
    if (p)
        free(p);

    return ret;
}

bool lowlevelWriteCmd(int fd, unsigned char *cdb_buf, unsigned cdb_len, unsigned char *dxf_buf, unsigned dxf_len)
{
    bool ret = false;
    unsigned char iobuf[SG_IOBUF_LEN] = { 0 };

    struct sg_io_hdr *p = (struct sg_io_hdr *) malloc(sizeof(struct sg_io_hdr));
    if (!p) {
        return ret;
    }
    memset(p, 0, sizeof(struct sg_io_hdr));

    p->interface_id = 'S';
    p->cmdp = cdb_buf;
    p->cmd_len = cdb_len;
    p->flags = SG_FLAG_LUN_INHIBIT;
    p->dxfer_direction = SG_DXFER_TO_DEV;
    p->dxferp = dxf_buf;
    p->dxfer_len = dxf_len;
    p->sbp = iobuf;
    p->mx_sb_len = SG_IOBUF_LEN;
    p->timeout = SG_TIMEOUT;

    if (ioctl(fd, SG_IO, p) < 0) {
        printf("ioctl error: errno=%d (%s)\n", errno, strerror(errno));
        goto llcmd_fail;
    }

#ifdef SCSI_DEBUG
    printf("duration: %d ms status: 0x%x host_status 0x%x driver_status 0x%x resid %d\n",
        p->duration, p->status, p->host_status, p->driver_status, p->resid);
#endif

    if (p->resid == 0) {
        ret = true;
    }

llcmd_fail:
    if (p)
        free(p);

    return ret;
}

unsigned lowlevelServiceCmd(int fd, unsigned char code)
{
    unsigned char rxbuf[16] = { 0 };
    unsigned char cdb[16] = { 0xc5, 7, 0, 0, 0, 0, 0, 0, 0, 0x10, 0xff, code, 0, 0, 0, 0 };

    bool ok = lowlevelCmd(fd, cdb, sizeof(cdb), rxbuf, sizeof(rxbuf));
    if (!ok) {
        return -1;
    }

    // return first 4 bytes
    return *((unsigned*)rxbuf);
}

bool lowlevelReadCmd(int fd, unsigned char *buf, unsigned chunk_size, unsigned addr)
{
    // interpret arguments as arrays of bytes
    unsigned char cs[4] = { 0 };
    unsigned char ad[4] = { 0 };
    *((unsigned*)cs) = chunk_size;
    *((unsigned*)ad) = addr;

    // create cmd packet
    unsigned char cdb[16] = { 0xc3, 7, ad[3], ad[2], ad[1], ad[0], cs[3], cs[2], cs[1], cs[0], 0, 0, 0, 0, 0, 0 };

    return lowlevelCmd(fd, cdb, sizeof(cdb), buf, chunk_size);
}

bool ServiceIsFinished(int fd)
{
    unsigned char ret = lowlevelServiceCmd(fd, 0x04);
    return (ret == 0x10);
}

bool ServiceIsLocked(int fd)
{
    unsigned char ret = lowlevelServiceCmd(fd, 0x03);
    return !(ret == 0x10);
}

bool ServiceLock(int fd)
{
    unsigned char ret = lowlevelServiceCmd(fd, 0x05);
    return (ret == 0x10);
}

bool ServiceUnlock(int fd)
{
    unsigned char ret = lowlevelServiceCmd(fd, 0x06);
    return !(ret == 0x10);
}

bool ServiceOpen(int fd)
{
    while (ServiceIsFinished(fd)) {
        if (!ServiceIsLocked(fd)) {
            break;
        }

        usleep(10000);
    }

    if (ServiceIsLocked(fd)) {
        ServiceUnlock(fd);
    }

    while (1) {
        if (ServiceLock(fd)) {
            return true;
        }

        usleep(10000);
    }

    return false;
}

bool ServiceClose(int fd)
{
    while (!ServiceIsFinished(fd)) {
        printf(".");
        usleep(10000);
    }

    return ServiceUnlock(fd);
}

bool VendorCmdGetData(int fd, unsigned char code, unsigned char *buf, unsigned char buflen)
{
    bool ret = false;

    memset(buf, 0, buflen);

    if (!ServiceOpen(fd)) {
        return false;
    }

    unsigned char cdb[16] = { 0xc5, 7, 0, 0, 0, 0, 0, 0, 0, buflen, 2, 1, code, 0, 0, 0 };

    bool ok = lowlevelCmd(fd, cdb, sizeof(cdb), buf, buflen);
    if (!ok) {
        goto vcgd_fail;
    }

    ServiceIsFinished(fd);

    cdb[11] = 2;
    ok = lowlevelCmd(fd, cdb, sizeof(cdb), buf, buflen);
    if (!ok) {
        goto vcgd_fail;
    }

    ret = true;

vcgd_fail:
    ServiceClose(fd);
    return ret;
}

bool VendorCmdSetData(int fd, unsigned char code, unsigned char *data, unsigned char datalen)
{
    bool ret = false;

    if (!ServiceOpen(fd)) {
        return false;
    }

    unsigned char cdb[16] = { 0xc5, 7, 0, 0, 0, 0, 0, 0, 0, datalen, 2, 3, code, 0, 0, 0 };

    bool ok = lowlevelWriteCmd(fd, cdb, sizeof(cdb), data, datalen);
    if (!ok) {
        printf("VendorCmdSetData fail 1\n");
        goto vcgd_fail;
    }

    ServiceIsFinished(fd);

    ret = true;

vcgd_fail:
    ServiceClose(fd);
    return ret;
}

bool initDevice(int fd) {
    unsigned char data[4] = { 4, 0, 0, 0 };

    if(!VendorCmdSetData(fd, 0, data, 4))
        return false;

    usleep(50000);
    
    data[0] = 6;

    if(!VendorCmdSetData(fd, 0, data, 4))
        return false;

    usleep(50000);

    return true;
}

// enums suffixed with "xx" are not original
typedef enum {
    STATE_IDLE, STATE_SCAN, STATE_AUTOCAL, STATE_AUTOCAL_MOVE, STATE_NOT_CAL, STATE_INVALIDxx
} DeviceState_t;

char state_lut[][13] = { "IDLE", "SCAN", "AUTOCAL", "AUTOCAL_MOVE", "NOT_CAL" };

DeviceState_t GetDeviceState(int fd)
{
    unsigned buf = 0;

    if (!VendorCmdGetData(fd, 0, (unsigned char*)&buf, 4)) {
        return STATE_INVALIDxx;
    }

    return (DeviceState_t)buf;
}

bool GetDeviceDataInfo(int fd, DataInfo_t *out)
{
    return VendorCmdGetData(fd, 1, (unsigned char*)out, sizeof(DataInfo_t));
}

bool MemoryRead(int fd, int addr, unsigned char *imgbuf, unsigned imgbufsize)
{
    unsigned chunk_size = 0x10000;

    if (chunk_size > imgbufsize) {
        chunk_size = imgbufsize;
    }

    unsigned char *buf = imgbuf;
    int remaining_bytes = imgbufsize;

    // omitted weird handling when (addr&3) == true

    while (remaining_bytes > 0) {
        // read chunk of data
        bool ok = lowlevelReadCmd(fd, buf, chunk_size, addr);
        if (!ok) {
            printf("MemoryRead fail\n");
            return false;
        }

        printf("read chunk of 0x%x bytes, start addr 0x%x, bufptr 0x%p\n", chunk_size, addr, (void*)buf);
        remaining_bytes -= chunk_size;

        // pointer to next data
        buf += chunk_size;
        addr += chunk_size;

        if (chunk_size > remaining_bytes) {
            chunk_size = remaining_bytes;
        }
    }

    return true;
}

bool shuffleBitmap(unsigned char *imgbuf, unsigned imgbufsize, int width, int height, DI_Color_t color)
{
    unsigned char *dst = (unsigned char *)malloc(imgbufsize);
    if (!dst) {
        return false;
    }

    unsigned pos = 0, index = 0;
    if (color == DI_COLOR_COLOR) {
        for (int y = 0; y < height; y++) {
	        pos = (y * 3 * width) + 3 * width - 1;
            for (int x = 0; x < width; x++) {
                dst[pos - 2] = imgbuf[index];
                dst[pos - 1] = imgbuf[index + width];
                dst[pos] = imgbuf[index + 2*width];
//                dst[pos++] = 127;
                index++;
		        pos -= 3;
            }

            index += 2*width;
        }
    } else {
    }

    memcpy(imgbuf, dst, imgbufsize);

    free(dst);
    return true;
}

bool scsi_inquiry(int fd, char *model) {
    unsigned char inquiry_cmd[] = {0x12, 0, 0, 0, 36, 0};
    unsigned char inquiry_buf[36];

    bool ok = lowlevelCmd(fd, inquiry_cmd, sizeof(inquiry_cmd), inquiry_buf, sizeof(inquiry_buf));

    if (ok) {
        memcpy(model, inquiry_buf + 16, 16);
        model[16] = '\0';
    }

    return ok;
}

bool checkDevice(int fd)
{
    unsigned rxbuf = 0;
    unsigned char cdb[16] = { 0xc5, 7, 0, 0, 0, 0, 0, 0, 0, 4, 0xff, 2, 0, 0, 0, 0 };

    bool ok = lowlevelCmd(fd, cdb, sizeof(cdb), (unsigned char*)&rxbuf, 4);
    if (!ok) {
        return false;
    }

    if ((unsigned)rxbuf == 0x41564f4e) {
        return true;
    }

    return false;
}

SANE_Status sane_mscan_init(SANE_Int *version_code, SANE_Auth_Callback authorize) {
    *version_code = SANE_VERSION_CODE(1, 0, 0);

    option_count_descriptor.name = "option-count";
    option_count_descriptor.desc = "Option Count";

    return SANE_STATUS_GOOD;
}

SANE_Status sane_mscan_get_devices(const SANE_Device ***list, SANE_Bool local_only) {
    DIR *dev_dir;
    struct dirent *entry;
    char path[261];
    char model[17];
    
    dev_dir = opendir("/dev");
    
    if (!dev_dir) {
        return SANE_STATUS_IO_ERROR;
    }

    while ((entry = readdir(dev_dir)) != NULL) {
        if (strncmp(entry->d_name, "sg", 2) == 0) {
            snprintf(path, sizeof(path), "/dev/%s", entry->d_name);

            int fd = open(path, O_RDWR);

            if(scsi_inquiry(fd, model)) {
                if (strncmp(model, "MagicScan", 9) == 0 && checkDevice(fd)) {
                    device_list[device_count].name = strdup(path);
                    device_list[device_count].vendor = "Hyundai";
                    device_list[device_count].model = "MagicScan";
                    device_list[device_count].type = "handheld scanner";
                    device_ptrs[device_count] = &device_list[device_count];
                    device_count++;
                }
            }

            close(fd);
        }
    }

    closedir(dev_dir);

    device_ptrs[device_count] = NULL;

    *list = device_ptrs;

    return SANE_STATUS_GOOD;
}

SANE_Status sane_mscan_open (SANE_String_Const name, SANE_Handle *handle) {
    int fd = open(name, O_RDWR);

    if (fd < 0) {
        return SANE_STATUS_INVAL;
    }

    if(!initDevice(fd))
        return SANE_STATUS_INVAL;

    MagicScanHandle *h = malloc(sizeof(MagicScanHandle));

    if (!h) {
        close(fd);
        return SANE_STATUS_NO_MEM;
    }

    h->fd = fd;
    
    *handle = (SANE_Handle)h;

    return SANE_STATUS_GOOD;
}

void sane_mscan_close (SANE_Handle handle) {
    MagicScanHandle *h = (MagicScanHandle *)handle;
    close(h->fd);
    free(h);
}

SANE_Status sane_mscan_start (SANE_Handle *handle) {
    MagicScanHandle *h = (MagicScanHandle *)handle;

    return SANE_STATUS_GOOD;
}

SANE_Status sane_mscan_read(SANE_Handle handle, SANE_Byte * buf, SANE_Int maxlen, SANE_Int * len) {
    MagicScanHandle *h = (MagicScanHandle *)handle;

    DeviceState_t state;

    while((state = GetDeviceState(h->fd)) == STATE_IDLE) {}

    while((state = GetDeviceState(h->fd)) == STATE_SCAN) {
        if (imgbuf != NULL) {
            unsigned int remaining_bytes = global_imgbufsize - offset;
            
            unsigned int to_copy = (remaining_bytes < (unsigned)maxlen) ? remaining_bytes : (unsigned)maxlen;

            memcpy(buf, &imgbuf[offset], to_copy);

            *len = to_copy;

            if (to_copy == remaining_bytes) {
                global_imgbufsize = 0;
                free(imgbuf);
                imgbuf = NULL;
            } else {
                offset += to_copy;
            }
            
            return SANE_STATUS_GOOD;
        }

        DataInfo_t datainfo;

        if (state >= STATE_INVALIDxx || state < 0) {
            return SANE_STATUS_IO_ERROR;
        }

        if (!GetDeviceDataInfo(h->fd, &datainfo)) {
            return SANE_STATUS_IO_ERROR;
        }
        
        if (datainfo.status < 0 || datainfo.status > 2) {
            return SANE_STATUS_IO_ERROR;
        }

        if (datainfo.status != DI_STATUS_NOT_READY) {
            // there's data for us
            unsigned int imgbufsize = datainfo.width * datainfo.height;

            if (datainfo.color == DI_COLOR_COLOR) {
                imgbufsize *= 3;
            }

            // image buffer
            if (imgbuf == NULL) {
                imgbuf = (unsigned char *)malloc(imgbufsize);
                global_imgbufsize = imgbufsize;
                offset = 0;
            }

            if (!imgbuf)
                return SANE_STATUS_NO_MEM;

            // read data
            bool ok = MemoryRead(h->fd, datainfo.addr, imgbuf, imgbufsize);
                
            if (!ok) {
                free(imgbuf);
                return SANE_STATUS_IO_ERROR;
            }

            shuffleBitmap(imgbuf, imgbufsize, datainfo.width, datainfo.height, datainfo.color);

            unsigned to_copy = (imgbufsize < (unsigned)maxlen) ? imgbufsize : (unsigned)maxlen;
            memcpy(buf, imgbuf, to_copy);

            *len = to_copy;

            if (to_copy == imgbufsize) {
                global_imgbufsize = 0;
                free(imgbuf);
                imgbuf = NULL;
            } else {
                offset += to_copy;
            }
            
            return SANE_STATUS_GOOD;
        }

        usleep(10000);
    }

    *len = 0;

    if (state == STATE_IDLE) {
        return SANE_STATUS_EOF;
    }
    else
        return SANE_STATUS_IO_ERROR;
}

SANE_Status sane_mscan_control_option(SANE_Handle h, SANE_Int n, SANE_Action a, void *v, SANE_Int * i) {
    switch(a) {
        case SANE_ACTION_GET_VALUE:
            if (n == 0)
                *((SANE_Int *)v) = 1;
            break;
        case SANE_ACTION_SET_VALUE:
            break;
        case SANE_ACTION_SET_AUTO:
            break;
    }

    return SANE_STATUS_GOOD;
}

SANE_Status sane_mscan_get_parameters (SANE_Handle *handle, SANE_Parameters *p) {
    MagicScanHandle *h = (MagicScanHandle *)handle;

    DeviceState_t state = GetDeviceState(h->fd);

    SANE_Parameters params;

    params.format = SANE_FRAME_RGB;
    params.last_frame = SANE_TRUE;
    params.pixels_per_line = 2560;
    params.bytes_per_line = 3*2560;
    params.lines = -1;
    params.depth = 8;

    *p = params;

    return SANE_STATUS_GOOD;
}


const SANE_Option_Descriptor * sane_mscan_get_option_descriptor(SANE_Handle h, SANE_Int n) {
    switch (n) {
        case 0:
            return &option_count_descriptor;
        default:
            return NULL;
    }
}