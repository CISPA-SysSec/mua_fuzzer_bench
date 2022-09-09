source("plot_scripts/setup.R")

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
