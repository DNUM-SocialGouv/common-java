# ProConnect Java Integration

Ce projet présente une intégration avec ProConnect utilisant Jakarta EE, Spring MVC et Java 21.

## Table des matières

1. [Prérequis](#prérequis)
2. [Configuration](#configuration)
3. [Environnements](#environnements)
4. [Comptes de test](#comptes-de-test)
5. [Démarrage rapide](#démarrage-rapide)
6. [Tests](#tests)
7. [Swagger](#swagger)

## Prérequis

- JDK 21
- Maven

## Configuration

Il est nécessaire de créer un projet dans le backoffice ProConnect.
La page de Configuration se trouve [ici](https://partenaires.proconnect.gouv.fr/apps).

De cette configuration sont fournis le "Client ID" et le "Client Secret".
Renseigner ces informations dans la classe "fr.gouv.dnum.proconnect.web.proconnect.Constants".

À notre charge de configurer dans ce back-office les URLs suivantes :

- URL de la page de redirection : `http://localhost:8080/proconnect/valid_code`
- URL de déconnexion : `http://localhost:8080/proconnect/logout`

Pour l'algorithme de signature, sélectionner ES256.

## Environnements

Voici la liste des différents environnements mis à disposition par ProConnect.
Par simplicité l'environnement d'intégration ouvert sur internet sera utilisé :

| Type | Environnement | URL |
|------|---------------|-----|
| INTERNET | Intégration | `fca.integ01.dev-agentconnect.fr` |
| INTERNET | Production | `auth.agentconnect.gouv.fr` |
| RIE | Intégration | `fca.integ02.agentconnect.rie.gouv.fr` |
| RIE | Production | `auth.agentconnect.rie.gouv.fr` |

## Comptes de test

Les comptes de test suivants sont disponibles :
```
test@fia1.fr / test@fia1.fr

user@yopmail.com / user@yopmail.com
```

[Autres](https://github.com/numerique-gouv/proconnect-identite/blob/master/scripts/fixtures.sql#L10) comptes disponibles.

## Démarrage rapide 

Depuis la racine du projet, lancer la commande :

```
mvn clean package
```

Puis :

```
java -jar target/proconnect-1.0-SNAPSHOT.jar
```

## Tests

1. Ouvrir un onglet sur : http://localhost:8080/proconnect/link
2. Avec l'URL renvoyée ouvrir un autre onglet
3. Pour se déconnecter, ouvrir un onglet sur : http://localhost:8080/proconnect/disconnect

## Swagger

Le Swagger est disponible [ici](http://localhost:8080/public/swagger-ui/index.html).