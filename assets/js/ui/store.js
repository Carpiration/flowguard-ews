// Хранилище отчётов в IndexedDB этого браузера. Если IndexedDB недоступна
// (например, приватный режим), используется память вкладки — до её закрытия.

const DB_NAME = 'flowguard';
const DB_VERSION = 1;
let dbPromise = null;
const memory = { meta: new Map(), reports: new Map() };
export const storeState = { persistent: true };

function open() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve) => {
    let req;
    try {
      req = indexedDB.open(DB_NAME, DB_VERSION);
    } catch {
      storeState.persistent = false;
      resolve(null);
      return;
    }
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('reports')) db.createObjectStore('reports', { keyPath: 'id' });
      if (!db.objectStoreNames.contains('meta')) db.createObjectStore('meta', { keyPath: 'id' }).createIndex('createdAt', 'createdAt');
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => {
      storeState.persistent = false;
      resolve(null);
    };
    req.onblocked = () => {
      storeState.persistent = false;
      resolve(null);
    };
  });
  return dbPromise;
}

function tx(db, stores, mode, fn) {
  return new Promise((resolve, reject) => {
    const t = db.transaction(stores, mode);
    const out = fn(t);
    t.oncomplete = () => resolve(out?.result ?? out);
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error || new Error('Транзакция прервана'));
  });
}

export function metaOf(r) {
  return {
    id: r.id,
    createdAt: r.createdAt,
    name: r.source?.name || 'Без названия',
    kind: r.source?.kind || 'file',
    format: r.source?.format || '',
    size: r.source?.size || 0,
    risk: r.risk.peak,
    level: r.risk.level,
    incidents: r.incidents.length,
    maxSev: r.incidents.reduce((m, i) => Math.max(m, i.sev), 0),
    packets: r.stats.packets,
    duration: r.stats.duration,
    labelled: Boolean(r.evaluation),
  };
}

export async function saveReport(report) {
  const db = await open();
  const meta = metaOf(report);
  if (!db) {
    memory.meta.set(meta.id, meta);
    memory.reports.set(report.id, report);
    return meta;
  }
  await tx(db, ['reports', 'meta'], 'readwrite', (t) => {
    t.objectStore('reports').put(report);
    t.objectStore('meta').put(meta);
  });
  return meta;
}

export async function listMeta() {
  const db = await open();
  let items;
  if (!db) items = [...memory.meta.values()];
  else {
    items = await new Promise((resolve, reject) => {
      const req = db.transaction('meta').objectStore('meta').getAll();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
  return items.sort((a, b) => b.createdAt - a.createdAt);
}

export async function getReport(id) {
  const db = await open();
  if (!db) return memory.reports.get(id) || null;
  return new Promise((resolve, reject) => {
    const req = db.transaction('reports').objectStore('reports').get(id);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

export async function deleteReports(ids) {
  const db = await open();
  if (!db) {
    for (const id of ids) {
      memory.meta.delete(id);
      memory.reports.delete(id);
    }
    return;
  }
  await tx(db, ['reports', 'meta'], 'readwrite', (t) => {
    for (const id of ids) {
      t.objectStore('reports').delete(id);
      t.objectStore('meta').delete(id);
    }
  });
}

export async function clearAll() {
  const db = await open();
  memory.meta.clear();
  memory.reports.clear();
  if (!db) return;
  await tx(db, ['reports', 'meta'], 'readwrite', (t) => {
    t.objectStore('reports').clear();
    t.objectStore('meta').clear();
  });
}

export function isReport(obj) {
  return Boolean(obj && typeof obj === 'object' && obj.id && obj.risk && obj.timeline && Array.isArray(obj.incidents) && obj.stats);
}
