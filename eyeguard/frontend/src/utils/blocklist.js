export const emptyBlocklistSnapshot = Object.freeze({
  count: 0,
  items: [],
  updated_at: null,
  details: [],
});

const normalizeItems = (payload) => {
  if (!payload || typeof payload !== 'object') {
    return [];
  }
  const rawItems = Array.isArray(payload.items)
    ? payload.items
    : Array.isArray(payload)
      ? payload
      : [];
  return rawItems
    .map((entry) => {
      if (typeof entry === 'string') {
        return entry.trim();
      }
      if (entry && typeof entry === 'object' && typeof entry.ip === 'string') {
        return entry.ip.trim();
      }
      return null;
    })
    .filter((ip) => typeof ip === 'string' && ip.length > 0);
};

export const normalizeBlocklistPayload = (payload) => {
  const items = normalizeItems(payload);
  const uniqueItems = Array.from(new Set(items));

  const detailsMap = new Map();
  const rawDetails = payload && Array.isArray(payload.details) ? payload.details : [];
  rawDetails.forEach((entry) => {
    if (!entry) {
      return;
    }
    if (typeof entry === 'string') {
      const ipValue = entry.trim();
      if (ipValue) {
        detailsMap.set(ipValue, { ip: ipValue, blocked_by: null, created_at: null });
      }
      return;
    }
    const ipValue = typeof entry.ip === 'string' ? entry.ip.trim() : '';
    if (!ipValue) {
      return;
    }
    detailsMap.set(ipValue, {
      ip: ipValue,
      blocked_by:
        typeof entry.blocked_by === 'string'
          ? entry.blocked_by
          : entry.blocked_by ?? null,
      created_at: entry.created_at ?? null,
    });
  });

  uniqueItems.forEach((ip) => {
    const key = ip.trim();
    if (key && !detailsMap.has(key)) {
      detailsMap.set(key, { ip: key, blocked_by: null, created_at: null });
    }
  });

  const countValue =
    payload && typeof payload.count === 'number' && Number.isFinite(payload.count)
      ? payload.count
      : uniqueItems.length;
  const updatedAtValue =
    payload && typeof payload.updated_at === 'string' && payload.updated_at.length
      ? payload.updated_at
      : null;

  return {
    count: countValue,
    items: uniqueItems,
    updated_at: updatedAtValue,
    details: Array.from(detailsMap.values()),
  };
};

const isValidIPv4 = (value) => {
  if (typeof value !== 'string') {
    return false;
  }
  const segments = value.trim().split('.');
  if (segments.length !== 4) {
    return false;
  }
  return segments.every((segment) => {
    if (!/^[0-9]{1,3}$/.test(segment)) {
      return false;
    }
    if (segment.length > 1 && segment.startsWith('0')) {
      return false;
    }
    const number = Number(segment);
    return number >= 0 && number <= 255;
  });
};

const isValidHextet = (segment) => /^[0-9a-f]{1,4}$/i.test(segment);

const isValidIPv6 = (value) => {
  if (typeof value !== 'string') {
    return false;
  }
  const input = value.trim();
  if (!input.length) {
    return false;
  }
  if (input === '::') {
    return true;
  }
  if (input.includes('::')) {
    if (input.indexOf('::') !== input.lastIndexOf('::')) {
      return false;
    }
    const [headRaw, tailRaw] = input.split('::');
    const headParts = headRaw ? headRaw.split(':').filter((part) => part.length > 0) : [];
    const tailPartsInitial = tailRaw ? tailRaw.split(':') : [];
    let ipv4Tail = null;
    if (tailPartsInitial.length && tailPartsInitial[tailPartsInitial.length - 1].includes('.')) {
      ipv4Tail = tailPartsInitial.pop();
      if (!isValidIPv4(ipv4Tail || '')) {
        return false;
      }
    }
    const tailParts = tailPartsInitial.filter((part) => part.length > 0);
    if (!headParts.every(isValidHextet) || !tailParts.every(isValidHextet)) {
      return false;
    }
    const totalParts = headParts.length + tailParts.length + (ipv4Tail ? 2 : 0);
    return totalParts < 8;
  }
  const parts = input.split(':');
  let ipv4Tail = null;
  if (parts[parts.length - 1].includes('.')) {
    ipv4Tail = parts.pop();
    if (!isValidIPv4(ipv4Tail || '')) {
      return false;
    }
    if (parts.length !== 6) {
      return false;
    }
  } else if (parts.length !== 8) {
    return false;
  }
  return parts.every(isValidHextet);
};

export const isValidIpAddress = (value) => isValidIPv4(value) || isValidIPv6(value);

export const toComparableIp = (value) => (typeof value === 'string' ? value.trim().toLowerCase() : '');

export const applyBlocklistSnapshot = (queryClient, payload) => {
  const snapshot = normalizeBlocklistPayload(payload);
  if (queryClient && typeof queryClient.setQueryData === 'function') {
    queryClient.setQueryData(['blocklist'], snapshot);
    queryClient.setQueryData(['blocked-ips'], snapshot);
  }
  return snapshot;
};
