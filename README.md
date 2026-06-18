# Panel licencji MobCash

Panel ma login email + haslo + obowiazkowe 2FA TOTP, paczki, licencje, akceptacje serwerow i API dla core.

## Start lokalny

1. Skopiuj `.env.example` do `.env` i ustaw `SETUP_TOKEN`.
2. Uruchom:

```bash
npm start
```

3. Wejdz na:

```text
http://localhost:3080/setup?token=TWOJ_SETUP_TOKEN
```

4. Utworz konto admina i dodaj sekret 2FA do aplikacji typu Google Authenticator / 2FAS / Authy.

Bez poprawnego kodu 2FA logowanie nie przejdzie, nawet gdy haslo jest poprawne.

## Flow licencji

1. W panelu dodajesz paczke, np. `mobcash`.
2. Tworzysz licencje dla klienta.
3. Klient wpisuje w core:

```yml
enabled: true
license-key: "MOB-XXXX-XXXX-XXXX"
api-url: "https://twojadomena.pl/api/v1/license/check"
public-key: |
  -----BEGIN PUBLIC KEY-----
  ...
  -----END PUBLIC KEY-----
offline-grace-hours: 48
```

4. Pierwsze odpalenie serwera tworzy w panelu status `pending`.
5. Dopiero gdy zaakceptujesz serwer w panelu, core zacznie dzialac.
6. Jesli panel/VPS padnie, core dziala z ostatniej poprawnej licencji przez `offline-grace-hours`, domyslnie 48h.
7. Gdy odlaczysz serwer albo wylaczysz/usuniesz licencje, kolejne sprawdzenie blokuje core.

## VPS

Najprostszy start przez `pm2`:

```bash
npm install -g pm2
pm2 start server.js --name mobcash-licencje
pm2 save
```

Za domena ustaw reverse proxy na port `3080`. W produkcji zostaw `COOKIE_SECURE=true` i uzywaj HTTPS.

## API dla core

Endpoint:

```text
POST /api/v1/license/check
```

Body JSON:

```json
{
  "productId": "mobcash",
  "licenseKey": "MC-XXXX",
  "serverId": "server-uuid",
  "serverIp": "1.2.3.4",
  "serverPort": 25565,
  "pluginVersion": "1.0.0"
}
```

Pierwsze odpalenie tworzy oczekujacy serwer. Musisz wejsc w panel i zaakceptowac ten serwer przy licencji.

Klucz publiczny do core:

```text
/admin/public-key
```
