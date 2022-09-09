options(repos = c(CRAN = "https://cran.rstudio.com"))

## First specify the packages of interest
packages = c('ggplot2', 'UpSetR', 'tidyr', 'dplyr', 'VennDiagram', 'ggupset', 'forcats', 'rjson', 'gsubfn')

## Now load or install&load all
package.check <- lapply(
  packages,
  FUN = function(x) {
    if (!require(x, character.only = TRUE)) {
      install.packages(x, dependencies = TRUE)
      library(x, character.only = TRUE)
    }
  }
)
rm(packages, package.check)

dir.create(file.path("plot", "fig"), showWarnings = FALSE)

################################################################################
# resampling
resampling_data <- as.data.frame(fromJSON(file="plot/tmp_data/resampling.json"))

mean(resampling_data$X10.kill)
median(resampling_data$X10.kill)
min(resampling_data$X10.kill)
max(resampling_data$X10.kill)

kill_data <- as.data.frame(resampling_data[, endsWith(colnames(resampling_data), ".kill")]) %>%
  rename_with(function(x) gsub("\\.kill", "", x)) %>%
  rename_with(function(x) gsub("X", "", x))

eh <- do.call(cbind, lapply(kill_data, summary)) %>%
  as.data.frame()
eh$type <- row.names(eh)

p <- eh %>%
  pivot_longer(cols=-type) %>%
  mutate(across(c('name'), as.numeric)) %>%
  rename('sample_size' = 'name') %>%
  ggplot(aes(x = sample_size, y = value, color = type)) +
  geom_line()
ggsave(p, file="plot/fig/resampling.pdf", width=4, height=3)
