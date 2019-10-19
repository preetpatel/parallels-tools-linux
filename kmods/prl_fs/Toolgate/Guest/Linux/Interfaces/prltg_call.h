/*
 * Copyright (C) 1999-2018 Parallels International GmbH. All Rights Reserved.
 */

#include "prltg.h"

extern int call_tg_sync(struct pci_dev *pdev, TG_REQ_DESC *sdesc);
extern struct TG_PENDING_REQUEST *call_tg_async_start(struct pci_dev *pdev, TG_REQ_DESC *sdesc);
extern void call_tg_async_wait(struct TG_PENDING_REQUEST *req);
extern void call_tg_async_cancel(struct TG_PENDING_REQUEST *req);
