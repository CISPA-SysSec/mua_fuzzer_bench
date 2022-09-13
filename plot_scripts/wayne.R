source("plot_scripts/setup.R")


data <- as.data.frame(fromJSON(file = "plot/tmp_data/wayne.json"))

head(data, 3)

total_count <- sprintf("Total Mutants Killed: %d", nrow(data))
total_count

p <- ggplot(data) +
    geom_venn(aes(A = `aflpp`, B = `afl`, C = `libfuzzer`, D = `honggfuzz`),
        stroke_size = 0.1, text_size = 4, set_name_size = 4) +
    annotate("text", x = 0, y = -1.9, label = total_count, size = 4) +
    labs(title = "Overlap of Killed Mutants between Fuzzers") +
    theme_void() +
    theme(plot.title = element_text(hjust = 0.5)) +
    xlim(c(-2, 2)) +
    ylim(c(-2, 1.3))
p
ggsave(p, filename = "plot/fig/wayne.pdf", device = "pdf", width = 5, height = 4.5)
