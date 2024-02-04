-- --------------------------------------------------------
-- Hostitel:                     192.168.0.4
-- Verze serveru:                10.11.2-MariaDB - Source distribution
-- OS serveru:                   Linux
-- HeidiSQL Verze:               12.4.0.6670
-- --------------------------------------------------------

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET NAMES utf8 */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;


-- Exportování struktury databáze pro
CREATE DATABASE IF NOT EXISTS `svarochat` /*!40100 DEFAULT CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci */;
USE `svarochat`;

-- Exportování struktury pro tabulka svarochat.Chats
CREATE TABLE IF NOT EXISTS `Chats` (
  `Id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `Title` varchar(128) DEFAULT '',
  `Created` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`Id`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=10 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

-- Export dat nebyl vybrán.

-- Exportování struktury pro tabulka svarochat.Messages
CREATE TABLE IF NOT EXISTS `Messages` (
  `Username` varchar(64) NOT NULL DEFAULT '',
  `ChatId` int(10) unsigned NOT NULL,
  `Data` varchar(2048) DEFAULT NULL,
  `Sent` datetime(6) NOT NULL DEFAULT current_timestamp(6),
  PRIMARY KEY (`Username`,`ChatId`,`Sent`) USING BTREE,
  KEY `FK_messages_chats` (`ChatId`) USING BTREE,
  CONSTRAINT `FK_messages_chats` FOREIGN KEY (`ChatId`) REFERENCES `Chats` (`Id`),
  CONSTRAINT `FK_messages_users` FOREIGN KEY (`Username`) REFERENCES `Users` (`Username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

-- Export dat nebyl vybrán.

-- Exportování struktury pro tabulka svarochat.Users
CREATE TABLE IF NOT EXISTS `Users` (
  `Username` varchar(64) NOT NULL,
  `Password` varchar(64) NOT NULL DEFAULT '',
  `FirstName` varchar(32) DEFAULT NULL,
  `LastName` varchar(32) DEFAULT NULL,
  `Registered` timestamp NOT NULL DEFAULT current_timestamp(),
  `Active` bit(1) NOT NULL DEFAULT b'1',
  `Image` varchar(64) DEFAULT NULL,
  `LastLogin` timestamp NULL DEFAULT NULL,
  `LastOnline` timestamp NULL DEFAULT NULL,
  `AuthToken` varchar(64) DEFAULT NULL,
  `AuthTokenCreated` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`Username`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

-- Export dat nebyl vybrán.

-- Exportování struktury pro tabulka svarochat.UsersToChats
CREATE TABLE IF NOT EXISTS `UsersToChats` (
  `Username` varchar(64) NOT NULL,
  `ChatId` int(10) unsigned NOT NULL,
  `IsAdmin` bit(1) NOT NULL DEFAULT b'0',
  `Added` datetime(6) NOT NULL DEFAULT current_timestamp(6),
  `Removed` datetime(6) DEFAULT NULL,
  `LastReaded` datetime(6) DEFAULT current_timestamp(6),
  PRIMARY KEY (`Username`,`ChatId`) USING BTREE,
  KEY `FK__chats` (`ChatId`) USING BTREE,
  CONSTRAINT `FK__chats` FOREIGN KEY (`ChatId`) REFERENCES `Chats` (`Id`),
  CONSTRAINT `FK__users` FOREIGN KEY (`Username`) REFERENCES `Users` (`Username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci;

-- Export dat nebyl vybrán.

/*!40103 SET TIME_ZONE=IFNULL(@OLD_TIME_ZONE, 'system') */;
/*!40101 SET SQL_MODE=IFNULL(@OLD_SQL_MODE, '') */;
/*!40014 SET FOREIGN_KEY_CHECKS=IFNULL(@OLD_FOREIGN_KEY_CHECKS, 1) */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40111 SET SQL_NOTES=IFNULL(@OLD_SQL_NOTES, 1) */;
