/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/acpi.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>

#include <bfdebug.h>
#include <bfvisr.h>
#include <bfhypercall.h>

static const struct pci_device_id visr_table[] = {
    { PCI_DEVICE(VISR_VENDOR, VISR_DEVICE) },
    { 0 }
};
MODULE_DEVICE_TABLE(pci, visr_table);

int visr_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
    return 0;
}

static struct pci_driver visr_driver = {
    .name = VISR_NAME,
    .id_table = visr_table,
    .probe = visr_probe
};


static int visr_open(struct inode *inode, struct file *file)
{
    BFDEBUG("visr_open succeeded\n");
    return 0;
}

static int visr_release(struct inode *inode, struct file *file)
{
    BFDEBUG("visr_release succeeded\n");
    return 0;
}

static long ioctl_emulate(unsigned long arg)
{
    int ret;
    uint64_t bdf = 0;
    uint64_t __user *ptr = (uint64_t __user *)arg;

    get_user(bdf, ptr);

    ret = __visr_op__emulate(bdf);
    if (ret == FAILURE) {
        BFDEBUG("visr: emulate failed");
    }

    return ret;
}

static long ioctl_map_mcfg(void)
{
    int ret;
    struct acpi_table_mcfg *mcfg = NULL;

    acpi_get_table(ACPI_SIG_MCFG, 0, (struct acpi_table_header **)&mcfg);
    ret = __visr_op__map_mcfg((uintptr_t)mcfg);

    if (ret == FAILURE) {
        BFDEBUG("visr: map_mcfg failed");
    }

    return ret;
}

static long
visr_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
        case IOCTL_MAP_MCFG:
            return ioctl_map_mcfg();
        case IOCTL_EMULATE:
            return ioctl_emulate(arg);
        default:
            return -EINVAL;
    }
}

/* data structures */

static struct file_operations visr_fops = {
    .open = visr_open,
    .release = visr_release,
    .unlocked_ioctl = visr_unlocked_ioctl
};

static struct miscdevice visr_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = VISR_NAME,
    .fops = &visr_fops,
    .mode = 0666
};

/* init/exit */

int visr_init(void)
{
    int ret = misc_register(&visr_misc);
    if (ret) {
        printk("visr: misc_register failed\n");
        return ret;
    }

    ret = pci_register_driver(&visr_driver);
    if (ret < 0) {
        printk("visr: pci_register_driver failed\n");
        return ret;
    }

    printk("visr: init succeeded\n");
    return 0;
}

void visr_exit(void)
{
    misc_deregister(&visr_misc);
    pci_unregister_driver(&visr_driver);

    printk("visr: exit succeeded\n");

    return;
}

module_init(visr_init);
module_exit(visr_exit);

MODULE_LICENSE("GPL");
