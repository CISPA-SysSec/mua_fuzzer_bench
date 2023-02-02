source("plot_scripts/setup.R")

################################################################################
# resampling
muta_data <- as.data.frame(read.csv(file = "plot_scripts/data/mutation_types_per_fuzzer.csv"))
print(head(muta_data))

p <- muta_data %>%
    mutate(not_found = covered - found, not_covered = done - covered) %>%
    mutate(Found = found / done, Covered = not_found / done) %>%
    mutate(pattern_name = gsub('_', ' ', pattern_name)) %>%
    filter(covered > 0) %>%
    # pivot_longer(cols = c(not_covered, not_found, found)) %>%
    pivot_longer(cols = c(Found, Covered)) %>%
# print(head(p))
    ggplot(aes(x = fuzzer, y = value, fill = name)) +
    facet_wrap(~pattern_name, labeller = label_wrap_gen(width = 15)) +
    scale_y_continuous(labels = scales::percent) +
    geom_col() +
    theme(
        legend.position = "bottom",
        axis.title.x = element_blank(),
        strip.text = element_text(size = 9),
        axis.text.x = element_text(angle = 90, vjust=0.5, hjust=1)
        # panel.background = element_blank(),
        # panel.grid.major = element_line(size = 0.5, linetype = 'solid', colour = 'black'),
    ) +
    labs(y = "Percentage of Mutants", fill = "Result")
  #filter(fuzzer == "aflpp") %>%
#   ggplot(aes(x = factor(name, levels = positions), y = value, label = sprintf("%3.1f%%", value * 100))) +
#   geom_col(aes(fill = factor(name, levels = positions))) +
#   geom_text(vjust = "inward", size = 2.5) +
#   scale_y_continuous(labels = scales::percent, expand = c(0, 0.01)) +
#   scale_fill_discrete(labels = c("default+asan", "default", "asan")) +
#   facet_wrap(c("prog"), nrow = 1) +
#   labs(fill = "Found By", x = "Subject", y = "Percentage of Covered Mutations") +
#   theme(legend.position = "top", axis.title.x = element_blank())
#p
ggsave(p, filename = "plot/fig/mutation_types.pdf", device = "pdf", width=8, height = 10)