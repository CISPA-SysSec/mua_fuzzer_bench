options(repos = c(CRAN = "https://cran.rstudio.com"))

## First specify the packages of interest
packages <- c(
  "ggplot2", "UpSetR", "tidyr", "dplyr", "VennDiagram", "ggupset", "forcats", "rjson", "gsubfn", "ggvenn", "DBI",
  "RSQLite", "extrafont"
)


## Now load or install&load all
package_check <- lapply(
  packages,
  FUN = function(x) {
    if (!require(x, character.only = TRUE)) {
      install.packages(x, dependencies = TRUE)
      library(x, character.only = TRUE)
    }
  }
)
rm(packages, package_check)

# font_import(prompt = FALSE)
# loadfonts()

dir.create(file.path("plot", "fig"), showWarnings = FALSE)
