source("plot_scripts/setup.R")

################################################################################
# resampling
resampling_data <- as.data.frame(fromJSON(file = "plot/tmp_data/resampling.json"))

kill_data <- as.data.frame(resampling_data[, endsWith(colnames(resampling_data), ".kill")]) %>%
  rename_with(function(x) gsub("\\.kill", "", x)) %>%
  rename_with(function(x) gsub("X", "", x))

probs = c(0.5, 0.75, 0.90, 0.95, 0.99)

kill_data_summary <- do.call(cbind, lapply(kill_data, function(x) quantile(x, probs = probs))) %>%
  as.data.frame()
kill_data_summary$type <- as.numeric(sub("\\%", "", row.names(kill_data_summary)))
kill_data_summary$type <- factor(kill_data_summary$type, levels = kill_data_summary$type)

pivot_kill_data <- kill_data_summary %>%
  pivot_longer(cols = -type) %>%
  mutate(prog = sub("\\..*", "", name)) %>%
  mutate(fuzzer = sub("\\..*", "", sub(".*?\\.", "", name))) %>%
  mutate(size = sub(".*\\.", "", name)) %>%
  select(-name) %>%
  mutate(across(c("size"), as.numeric))

p <- pivot_kill_data %>%
  ggplot(aes(x = size, y = value, color = type)) +
  geom_line() +
  facet_grid(rows = vars(fuzzer), cols = vars(prog), scales = "free") +
  theme(
    axis.text.x = element_text(angle = 75, hjust = 1),
  ) +
  ylab("Error Percentage") +
  xlab("Sample Size") +
  labs(color = "Percentile") +
  scale_y_continuous(labels = scales::percent) +
  scale_color_discrete()

p

ggsave(p, file = "plot/fig/resampling.pdf", width = 8, height = 8)
