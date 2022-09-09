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
# `pdf(NULL)`

################################################################################
# oracle results
data = read.csv("def_asan_results.csv")

covered_v_found_per = data %>%
  select(prog, fuzzer, found___both, found__asan, found__def, covered___both, covered__asan, covered__def) %>%
  mutate(covered_cnt=(covered___both + covered__asan + covered__def)) %>%
  mutate(found_both_per=found___both / covered_cnt) %>%
  mutate(found_asan_per=found__asan / covered_cnt) %>%
  mutate(found_def_per=found__def / covered_cnt) %>%
  mutate(covered_per=1 - found_both_per - found_asan_per - found_def_per) %>%
  rename(both = found_both_per, covered = covered_per, asan = found_asan_per, default = found_def_per) %>%
  pivot_longer(cols = c(both, asan, default, covered))

covered_v_found_per

positions <- c("covered", "default", "asan", "both")

p <- covered_v_found_per %>%
  filter(fuzzer == "aflpp") %>%
  ggplot(aes(x=prog)) +
  geom_col(aes(fill=factor(name, levels=positions), y=value)) +
  scale_y_continuous(labels = scales::percent, expand = c(0, 0), limits = c(0, 1.01)) +
  labs(fill='Result', x="Subject", y="Percentage of Mutations")

ggsave(p, filename="oracle-percentages.pdf", device="pdf")


# ################################################################################
# # resampling
# resampling_data <- as.data.frame(fromJSON(file="resampling.json"))
# 
# mean(resampling_data$X10.kill)
# median(resampling_data$X10.kill)
# min(resampling_data$X10.kill)
# max(resampling_data$X10.kill)
# 
# kill_data <- as.data.frame(resampling_data[, endsWith(colnames(resampling_data), ".kill")]) %>%
#   rename_with(function(x) gsub("\\.kill", "", x)) %>%
#   rename_with(function(x) gsub("X", "", x))
# 
# eh <- do.call(cbind, lapply(kill_data, summary)) %>%
#   as.data.frame()
# eh$type <- row.names(eh)
# 
# p <- eh %>%
#   pivot_longer(cols=-type) %>%
#   mutate(across(c('name'), as.numeric)) %>%
#   rename('sample_size' = 'name') %>%
#   ggplot(aes(x = sample_size, y = value, color = type)) +
#   geom_line()
# ggsave(p, file="resample.pdf", width=4, height=3)

