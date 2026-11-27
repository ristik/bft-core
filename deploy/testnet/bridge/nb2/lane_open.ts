/**
 * How every lane command opens its wallet (driver.ts): without the installation check (gamma-check asks for it) and without the wallet
 * lock. The reference wallet's lock (native-bridge-plugins wallet/core.ts lockWallet) names the process and host that hold it; each driver
 * command runs in its own container, and rehearse_nb2.py `docker kill`s one that runs over its timeout, which leaves a lock naming a host
 * that no longer exists. Such a lock can't be told from a live one, so every later command on that wallet would refuse ("in use"). The lane
 * runs its commands one at a time, so it needs no lock (bft-core#1176 review R2-1).
 */
import type { OpenOptions } from '../../../wallet/core.js';

export const LANE_OPEN: OpenOptions = { check: false, lock: false };
