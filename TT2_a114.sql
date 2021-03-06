-- MySQL Script generated by MySQL Workbench
-- Mon Jun 21 15:42:51 2021
-- Model: New Model    Version: 1.0
-- MySQL Workbench Forward Engineering

SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';

-- -----------------------------------------------------
-- Schema mydb
-- -----------------------------------------------------

-- -----------------------------------------------------
-- Schema mydb
-- -----------------------------------------------------
CREATE SCHEMA IF NOT EXISTS `mydb` DEFAULT CHARACTER SET utf8 ;
USE `mydb` ;

-- -----------------------------------------------------
-- Table `mydb`.`usuario`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `mydb`.`usuario` (
  `id_usuario` INT NOT NULL AUTO_INCREMENT,
  `nombre` VARCHAR(66) NULL,
  `apellidos` VARCHAR(66) NULL,
  `correo` VARCHAR(50) NULL,
  `password` VARCHAR(64) NULL,
  `activo` INT NULL DEFAULT 0,
  PRIMARY KEY (`id_usuario`))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `mydb`.`administrador`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `mydb`.`administrador` (
  `id_administrador` VARCHAR(8) NOT NULL,
  `usuario_id_usuario` INT NOT NULL,
  PRIMARY KEY (`id_administrador`, `usuario_id_usuario`),
  INDEX `fk_administrador_usuario1_idx` (`usuario_id_usuario` ASC) VISIBLE,
  CONSTRAINT `fk_administrador_usuario1`
    FOREIGN KEY (`usuario_id_usuario`)
    REFERENCES `mydb`.`usuario` (`id_usuario`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `mydb`.`alumno`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `mydb`.`alumno` (
  `id_alumno` VARCHAR(12) NOT NULL,
  `usuario_id_usuario` INT NOT NULL,
  PRIMARY KEY (`id_alumno`, `usuario_id_usuario`),
  INDEX `fk_alumno_usuario1_idx` (`usuario_id_usuario` ASC) VISIBLE,
  CONSTRAINT `fk_alumno_usuario1`
    FOREIGN KEY (`usuario_id_usuario`)
    REFERENCES `mydb`.`usuario` (`id_usuario`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `mydb`.`profesor`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `mydb`.`profesor` (
  `id_profesor` VARCHAR(12) NOT NULL,
  `usuario_id_usuario` INT NOT NULL,
  PRIMARY KEY (`id_profesor`, `usuario_id_usuario`),
  INDEX `fk_profesor_usuario1_idx` (`usuario_id_usuario` ASC) VISIBLE,
  CONSTRAINT `fk_profesor_usuario1`
    FOREIGN KEY (`usuario_id_usuario`)
    REFERENCES `mydb`.`usuario` (`id_usuario`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `mydb`.`materia`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `mydb`.`materia` (
  `id_materia` INT NOT NULL AUTO_INCREMENT,
  `nombre` VARCHAR(60) NULL,
  `nivel` VARCHAR(8) NULL,
  PRIMARY KEY (`id_materia`))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `mydb`.`profesor_materia`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `mydb`.`profesor_materia` (
  `id_profesor_materia` INT NOT NULL,
  `profesor_id_profesor` VARCHAR(12) NOT NULL,
  `materia_id_materia` INT NOT NULL,
  PRIMARY KEY (`id_profesor_materia`, `profesor_id_profesor`, `materia_id_materia`),
  INDEX `fk_profesor_materia_profesor1_idx` (`profesor_id_profesor` ASC) VISIBLE,
  INDEX `fk_profesor_materia_materia1_idx` (`materia_id_materia` ASC) VISIBLE,
  CONSTRAINT `fk_profesor_materia_profesor1`
    FOREIGN KEY (`profesor_id_profesor`)
    REFERENCES `mydb`.`profesor` (`id_profesor`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_profesor_materia_materia1`
    FOREIGN KEY (`materia_id_materia`)
    REFERENCES `mydb`.`materia` (`id_materia`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `mydb`.`evaluacion`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `mydb`.`evaluacion` (
  `id_evaluacion` INT NOT NULL,
  `id_materia` INT NULL,
  `nombre_eval` VARCHAR(70) NULL,
  `estado` INT NULL,
  `tiempo_aplicacion` INT NULL,
  PRIMARY KEY (`id_evaluacion`))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `mydb`.`reactivo`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `mydb`.`reactivo` (
  `id_reactivo` INT NOT NULL AUTO_INCREMENT,
  `pregunta` LONGTEXT CHARACTER SET 'utf8' NULL,
  `opcion_correcta` VARCHAR(2) CHARACTER SET 'utf8' NULL,
  `tipo` VARCHAR(4) NULL,
  `id_materia` INT NULL,
  PRIMARY KEY (`id_reactivo`))
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `mydb`.`opcion`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `mydb`.`opcion` (
  `id_opcion` INT NOT NULL AUTO_INCREMENT,
  `reactivo_id_reactivo` INT NOT NULL,
  `opcion` LONGTEXT CHARACTER SET 'utf8' NULL,
  `indice` VARCHAR(2) NULL,
  PRIMARY KEY (`id_opcion`, `reactivo_id_reactivo`),
  INDEX `fk_opcion_reactivo1_idx` (`reactivo_id_reactivo` ASC) VISIBLE,
  CONSTRAINT `fk_opcion_reactivo1`
    FOREIGN KEY (`reactivo_id_reactivo`)
    REFERENCES `mydb`.`reactivo` (`id_reactivo`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `mydb`.`evaluacion_alumno`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `mydb`.`evaluacion_alumno` (
  `id_evaluacion_alumno` INT NOT NULL AUTO_INCREMENT,
  `alumno_id_alumno` VARCHAR(12) NOT NULL,
  `evaluacion_id_evaluacion` INT NOT NULL,
  `calificacion` INT NULL,
  `fecha_aplicacion` VARCHAR(20) NULL,
  PRIMARY KEY (`id_evaluacion_alumno`, `alumno_id_alumno`, `evaluacion_id_evaluacion`),
  INDEX `fk_evaluacion_alumno_alumno1_idx` (`alumno_id_alumno` ASC) VISIBLE,
  INDEX `fk_evaluacion_alumno_evaluacion1_idx` (`evaluacion_id_evaluacion` ASC) VISIBLE,
  CONSTRAINT `fk_evaluacion_alumno_alumno1`
    FOREIGN KEY (`alumno_id_alumno`)
    REFERENCES `mydb`.`alumno` (`id_alumno`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_evaluacion_alumno_evaluacion1`
    FOREIGN KEY (`evaluacion_id_evaluacion`)
    REFERENCES `mydb`.`evaluacion` (`id_evaluacion`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `mydb`.`evaluacion_profesor`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `mydb`.`evaluacion_profesor` (
  `id_evaluacion_profesor` INT NOT NULL AUTO_INCREMENT,
  `profesor_id_profesor` VARCHAR(12) NOT NULL,
  `evaluacion_id_evaluacion` INT NOT NULL,
  PRIMARY KEY (`id_evaluacion_profesor`, `evaluacion_id_evaluacion`, `profesor_id_profesor`),
  INDEX `fk_evaluacion_profesor_profesor1_idx` (`profesor_id_profesor` ASC) VISIBLE,
  INDEX `fk_evaluacion_profesor_evaluacion1_idx` (`evaluacion_id_evaluacion` ASC) VISIBLE,
  CONSTRAINT `fk_evaluacion_profesor_profesor1`
    FOREIGN KEY (`profesor_id_profesor`)
    REFERENCES `mydb`.`profesor` (`id_profesor`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_evaluacion_profesor_evaluacion1`
    FOREIGN KEY (`evaluacion_id_evaluacion`)
    REFERENCES `mydb`.`evaluacion` (`id_evaluacion`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `mydb`.`reactivo_evaluacion`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `mydb`.`reactivo_evaluacion` (
  `evaluacion_id_evaluacion` INT NOT NULL,
  `reactivo_id_reactivo` INT NOT NULL,
  PRIMARY KEY (`evaluacion_id_evaluacion`, `reactivo_id_reactivo`),
  INDEX `fk_reactivo_evaluacion_reactivo1_idx` (`reactivo_id_reactivo` ASC) VISIBLE,
  CONSTRAINT `fk_reactivo_evaluacion_evaluacion1`
    FOREIGN KEY (`evaluacion_id_evaluacion`)
    REFERENCES `mydb`.`evaluacion` (`id_evaluacion`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_reactivo_evaluacion_reactivo1`
    FOREIGN KEY (`reactivo_id_reactivo`)
    REFERENCES `mydb`.`reactivo` (`id_reactivo`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `mydb`.`respuesta_alumno_reactivo`
-- -----------------------------------------------------
CREATE TABLE IF NOT EXISTS `mydb`.`respuesta_alumno_reactivo` (
  `alumno_id_alumno` VARCHAR(12) NOT NULL,
  `reactivo_id_reactivo` INT NOT NULL,
  `evaluacion_id_evaluacion` INT NOT NULL,
  `respuesta_alumno` LONGTEXT NULL,
  PRIMARY KEY (`reactivo_id_reactivo`, `evaluacion_id_evaluacion`, `alumno_id_alumno`),
  INDEX `fk_respuesta_alunmno_reactivo_reactivo1_idx` (`reactivo_id_reactivo` ASC) VISIBLE,
  INDEX `fk_respuesta_alunmno_reactivo_evaluacion1_idx` (`evaluacion_id_evaluacion` ASC) VISIBLE,
  CONSTRAINT `fk_respuesta_alunmno_reactivo_alumno1`
    FOREIGN KEY (`alumno_id_alumno`)
    REFERENCES `mydb`.`alumno` (`id_alumno`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_respuesta_alunmno_reactivo_reactivo1`
    FOREIGN KEY (`reactivo_id_reactivo`)
    REFERENCES `mydb`.`reactivo` (`id_reactivo`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION,
  CONSTRAINT `fk_respuesta_alunmno_reactivo_evaluacion1`
    FOREIGN KEY (`evaluacion_id_evaluacion`)
    REFERENCES `mydb`.`evaluacion` (`id_evaluacion`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;


SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;

USE mydb;
INSERT INTO usuario VALUES(1,"Admin","administrador","admin@domain.com","c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f",1);
INSERT INTO administrador VALUES(10001,1);
