<p align="center"><img src="../assets/ddg-lion.svg" width="72" alt="DDG"></p>

# DDG — Architecture et conventions

## Frontière Rust / Go

Le binaire `ddg-agent` est un processus court piloté par JSON-lines. Une requête JSON arrive sur stdin et un objet enveloppe `{ok,data}` arrive sur stdout. Cette frontière limite le couplage entre le code système Rust et le code applicatif Go.

### Rust

Rust utilise `sysinfo` pour interroger les processus, puis calcule le SHA-256 du binaire en streaming. Le traitement n'exécute jamais le fichier analysé et le MVP ne tente pas de le modifier.

Le cœur est volontairement sans réseau : aucune clé API et aucun appel HTTP ne sont nécessaires au composant bas niveau.

### Go

Go orchestre `ddg-agent`, transforme les données, exécute les lookups en goroutines avec timeout et produit JSON ou texte. Les appels HTTP utilisent un client avec timeout explicite.

## Online lookup

VirusTotal est interrogé par `GET /api/v3/files/{id}` avec le SHA-256 comme identifiant et la clé dans l'en-tête `x-apikey`. Un fichier absent de la base produit `not_found`, pas `malicious`.

Les futures sources devraient implémenter la même forme conceptuelle :

```text
Provider.Check(ctx, hash) -> OnlineCheck
```

## Légitimité

Le champ `legitimacy` est conçu pour distinguer :

- une heuristique locale ;
- une preuve de signature numérique ;
- une réputation externe.

Ces signaux ne doivent pas être fusionnés en une affirmation absolue. Un binaire inconnu doit rester `unknown` tant qu'une preuve complémentaire n'est pas disponible.

## Sécurité à ajouter

1. Vérification Authenticode sur Windows.
2. Vérification Mach-O code signing / notarisation sur macOS.
3. Vérification des signatures de paquets et/ou ELF selon la distribution Linux.
4. Politique de réputation configurable.
5. Cache signé et hors ligne des verdicts.
6. Mode daemon avec permissions minimales.
7. Tests adversariaux sur noms de processus, chemins Unicode, liens symboliques et processus éphémères.
