import Dependencies._

ThisBuild / scalaVersion     := "3.8.4"
ThisBuild / version          := "1.0.0-dev"
ThisBuild / organization     := "com.cloud-apim"
ThisBuild / organizationName := "Cloud-APIM"

lazy val root = (project in file("."))
  .settings(
    name := "otoroshi-plugin-curity-phantom-token",
    scalacOptions ++= Seq(
      "-deprecation",
      "-feature",
      // wasm4s-bundle (transitive, provided) embeds an older scala 3 stdlib where `scala.caps` is
      // an object while scala-library 3.8.4 declares it as a package. Same suppression as otoroshi.
      "-Wconf:msg=package scala contains object and package with same name:s",
    ),
    libraryDependencies ++= Seq(
      "fr.maif" %% "otoroshi" % "18.0.0-preview2" % "provided",
      munit % Test
    )
  )
