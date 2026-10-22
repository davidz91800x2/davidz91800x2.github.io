// Aucune persistance automatique des clés, invitations ou opérations.
const encoder = new TextEncoder();
const b64 = bytes => {
  let chaine = '';
  for (const octet of bytes) chaine += String.fromCharCode(octet);
  return btoa(chaine);
};
const depuisB64 = chaine => Uint8Array.from(atob(chaine), c => c.charCodeAt(0));
const url64 = bytes => b64(bytes).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
function decoderSecret(chaine, longueur) {
  if (typeof chaine !== 'string' || !/^[A-Za-z0-9_-]+$/.test(chaine)) throw new Error('Invitation invalide.');
  const bytes = depuisB64(chaine.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - chaine.length % 4) % 4));
  if (bytes.length !== longueur || url64(bytes) !== chaine) throw new Error('Invitation invalide.');
  return bytes;
}
const aleatoire = n => crypto.getRandomValues(new Uint8Array(n));
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const hacher = async jeton => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(jeton))));
function adresseRelais(adresse) {
  const url = new URL(adresse);
  if (!(url.protocol === 'https:' || url.protocol === 'http:' && url.hostname === 'localhost')
    || url.username || url.password || url.hash || url.search || url.pathname !== '/') throw new Error('Adresse du relais invalide.');
  return url.origin;
}
const contexte = (id, op) => encoder.encode(JSON.stringify(['jsquad-relais-v1', id, op.appareil, op.seq]));

export class ErreurRelais extends Error {
  constructor(statut) { super(`Le relais a refusé la requête (${statut}).`); this.name = 'ErreurRelais'; this.statut = statut; }
}

export class ClientRelais {
  constructor({ relais, id, cle, lecture, ecriture, administration }, { fetch: transport = globalThis.fetch } = {}) {
    this.relais = adresseRelais(relais);
    if (!/^[0-9a-f]{32}$/.test(id)) throw new Error('Identifiant invalide.');
    decoderSecret(cle, 32); decoderSecret(lecture, 32);
    if (ecriture !== undefined) decoderSecret(ecriture, 32);
    if (administration !== undefined) decoderSecret(administration, 32);
    this.id = id; this.cle = cle; this.lecture = lecture; this.ecriture = ecriture;
    this.administration = administration; this.transport = transport;
    // Un nouvel appareil logique à chaque session évite les collisions de séquence après rechargement.
    this.appareil = hex(aleatoire(16)); this.seq = 0;
  }
  async requete(methode, suffixe, role, corps) {
    if (role && !this[role]) throw new Error('Droit insuffisant.');
    const headers = {};
    if (role) headers.Authorization = `Bearer ${this[role]}`;
    if (corps !== undefined) headers['Content-Type'] = 'application/json';
    const reponse = await this.transport(`${this.relais}/m/${this.id}${suffixe}`, {
      method: methode, headers, body: corps === undefined ? undefined : JSON.stringify(corps),
      credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer'
    });
    if (!reponse.ok) throw new ErreurRelais(reponse.status);
    return reponse.json();
  }
  lienInvitation(role, adresse = globalThis.location?.href) {
    if (!['equipage', 'invite'].includes(role)) throw new Error('Rôle invalide.');
    if (role === 'equipage' && !this.ecriture) throw new Error('Droit insuffisant.');
    const url = new URL(adresse);
    if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) throw new Error('Adresse d’invitation invalide.');
    const contenu = { version: 1, relais: this.relais, id: this.id, cle: this.cle, lecture: this.lecture };
    if (role === 'equipage') contenu.ecriture = this.ecriture;
    url.hash = `relais=${url64(encoder.encode(JSON.stringify(contenu)))}`;
    return url.href;
  }
  async cleCrypto() {
    return crypto.subtle.importKey('raw', decoderSecret(this.cle, 32), 'AES-GCM', false, ['encrypt', 'decrypt']);
  }
  async chiffrer(lot) {
    if (!this.ecriture) throw new Error('Droit insuffisant.');
    const texte = JSON.stringify(lot);
    if (texte === undefined) throw new Error('Lot JSON invalide.');
    const op = { appareil: this.appareil, seq: ++this.seq };
    const iv = aleatoire(12);
    const bloc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: contexte(this.id, op), tagLength: 128 },
      await this.cleCrypto(), encoder.encode(texte));
    return { ...op, iv: b64(iv), bloc: b64(new Uint8Array(bloc)) };
  }
  async dechiffrer(op) {
    try {
      const clair = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: depuisB64(op.iv),
        additionalData: contexte(this.id, op), tagLength: 128 }, await this.cleCrypto(), depuisB64(op.bloc));
      return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(clair));
    } catch { throw new Error('Déchiffrement impossible.'); }
  }
  envoyer(operation) { return this.requete('POST', '/ops', 'ecriture', operation); }
  async recevoir(depuisCurseur = 0, limite = 100) {
    if (!Number.isSafeInteger(depuisCurseur) || depuisCurseur < 0 || !Number.isInteger(limite) || limite < 1 || limite > 100) throw new Error('Pagination invalide.');
    const page = await this.requete('GET', `/ops?apres=${depuisCurseur}&limite=${limite}`, 'lecture');
    const lots = await Promise.all(page.operations.map(async op => ({ ...op, lot: await this.dechiffrer(op) })));
    return { ...page, operations: lots };
  }
  cloturer() { return this.requete('POST', '/cloture', 'administration'); }
  async purger() {
    await this.requete('DELETE', '', 'administration');
    try { await this.requete('GET', '/ops?apres=0', 'lecture'); }
    catch (erreur) { if (erreur.statut === 404) return { purgee: true, verification: 404 }; throw erreur; }
    throw new Error('Purge non confirmée.');
  }
}

export async function creerMission({ relais }, options = {}) {
  const client = new ClientRelais({ relais, id: hex(aleatoire(16)), cle: url64(aleatoire(32)),
    lecture: url64(aleatoire(32)), ecriture: url64(aleatoire(32)), administration: url64(aleatoire(32)) }, options);
  await client.requete('PUT', '', null, { lecture: await hacher(client.lecture),
    ecriture: await hacher(client.ecriture), administration: await hacher(client.administration) });
  return client;
}

export function lireInvitation(adresse, options = {}) {
  try {
    const url = new URL(adresse);
    if (!url.hash.startsWith('#relais=') || url.hash.length > 4096) throw new Error();
    const texte = url.hash.slice(8);
    if (!/^[A-Za-z0-9_-]+$/.test(texte)) throw new Error();
    const contenu = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(depuisB64(texte.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - texte.length % 4) % 4))));
    const cles = Object.keys(contenu).sort().join(',');
    if (contenu.version !== 1 || !['cle,id,lecture,relais,version', 'cle,ecriture,id,lecture,relais,version'].includes(cles)) throw new Error();
    return new ClientRelais(contenu, options);
  } catch { throw new Error('Invitation invalide.'); }
}
