source("plot_scripts/setup.R")


data <- as.data.frame(fromJSON(file = "plot/tmp_data/wayne.json"))

total_count <- sprintf("Total Mutants Killed: %d", nrow(data))

fuzzers <- colnames(data)

if (length(fuzzers) == 1) {
  venn_map <- aes(A = !!as.name(fuzzers[1]))
}
if (length(fuzzers) == 2) {
  venn_map <- aes(A = !!as.name(fuzzers[1]), B = !!as.name(fuzzers[2]))
}
if (length(fuzzers) == 3) {
  venn_map <- aes(A = !!as.name(fuzzers[1]), B = !!as.name(fuzzers[2]), C = !!as.name(fuzzers[3]))
}
if (length(fuzzers) == 4) {
  venn_map <- aes(
        A = !!as.name(fuzzers[1]), B = !!as.name(fuzzers[2]), C = !!as.name(fuzzers[3]), D = !!as.name(fuzzers[4])
    )
}

p <- ggplot(data) +
    geom_venn(venn_map,
        stroke_size = 0.1, text_size = 4, set_name_size = 4) +
    annotate("text", x = 0, y = -1.9, label = total_count, size = 4) +
    labs(title = "Overlap of Killed Mutants between Fuzzers") +
    theme_void() +
    theme(plot.title = element_text(hjust = 0.5)) +
    xlim(c(-2, 2)) +
    ylim(c(-1.9, 1.3))
p
ggsave(p, filename = "plot/fig/wayne.pdf", device = "pdf", width = 5, height = 4.5)
