source("plot_scripts/setup.R")

################################################################################
# resampling
muta_data <- as.data.frame(read.csv(file = "plot/tmp_data/mutation_types.csv"))

p <- muta_data %>%
    mutate(not_found = covered - found, not_covered = done - covered) %>%
    mutate(Found = found / done, Covered = not_found / done) %>%
    mutate(pattern_name = gsub("_", " ", pattern_name)) %>%
    filter(covered > 0) %>%
    # pivot_longer(cols = c(not_covered, not_found, found)) %>%
    pivot_longer(cols = c(Found, Covered)) %>%

    ggplot(aes(x = fuzzer, y = value, fill = name)) +
    facet_wrap(~pattern_name, labeller = label_wrap_gen(width = 15)) +
    scale_y_continuous(labels = scales::percent) +
    geom_col() +
    theme(
        legend.position = "bottom",
        axis.title.x = element_blank(),
        strip.text = element_text(size = 6),
        axis.text.x = element_text(angle = 90, vjust = 0.5, hjust = 1)
    ) +
    labs(y = "Percentage of Mutants", fill = "Result")

ggsave(p, filename = "plot/fig/mutation_types.pdf", device = "pdf", width = 5, height = 7)