source("plot_scripts/setup.R")

data <- read.csv("plot/tmp_data/def_asan_results.csv")

res <- data %>%
  select(prog, fuzzer, found___both, found__asan, found__def, covered___both, covered__asan, covered__def) %>%
  mutate(covered_cnt = (covered___both + covered__asan + covered__def)) %>%
  mutate(found_both_per = found___both / covered_cnt) %>%
  mutate(found_asan_per = found__asan / covered_cnt) %>%
  mutate(found_def_per = found__def / covered_cnt) %>%
  # mutate(covered_per=1 - found_both_per - found_asan_per - found_def_per) %>%
  select(-covered___both, -covered__asan, -covered_cnt, -covered__def) %>%
  rename(both = found_both_per, asan = found_asan_per, default = found_def_per) %>%
  pivot_longer(cols = c(both, asan, default)) %>%
  select(-found___both, -found__asan, -found__def)

head(res, 5)

positions <- c("both", "default", "asan")

p <- res %>%
  filter(fuzzer == "aflpp") %>%
  ggplot(aes(x = factor(name, levels = positions), y = value, label = sprintf("%3.1f%%", value * 100))) +
  geom_col(aes(fill = factor(name, levels = positions))) +
  geom_text(vjust = "inward", size = 2.5) +
  scale_y_continuous(labels = scales::percent, expand = c(0, 0.01)) +
  scale_fill_discrete(labels = c("default+asan", "default", "asan")) +
  facet_wrap(c("prog"), nrow = 1) +
  labs(fill = "Found By", x = "Subject", y = "Percentage of Covered Mutations") +
  theme(legend.position = "top", axis.title.x = element_blank())
p
# ggsave(p, filename = "plot/fig/oracle-percentages-aflpp.pdf", device = "pdf", width = 8, height = 2.5)

p <- res %>%
  ggplot(aes(x = factor(name, levels = positions), y = value, label = sprintf("%3.1f%%", value * 100))) +
  geom_col(aes(fill = factor(name, levels = positions))) +
  geom_text(vjust = "inward", size = 2.5) +
  scale_y_continuous(labels = scales::percent, expand = c(0, 0.01)) +
  scale_fill_discrete(labels = c("default+asan", "default", "asan")) +
  facet_grid(c("prog", "fuzzer"), scale = "free_y") +
  labs(fill = "Found By", x = "Subject", y = "Percentage of Covered Mutations") +
  theme(legend.position = "top", axis.title.x = element_blank())
p
# ggsave(p, filename = "plot/fig/oracle-percentages-full.pdf", device = "pdf", width = 5, height = 10)


# Stacked version
asan <- res[res$name %in% c("both", "asan"), ]
asan$type <- "asan"
def <- res[res$name %in% c("both", "default"), ]
def$type <- "default"

rejiggered <- merge(def, asan, all = TRUE)

head(rejiggered, 5)

t_pos <- c("default", "asan")
positions <- c("asan", "default", "both")

p <- rejiggered %>%
  filter(fuzzer == "aflpp") %>%
  ggplot(aes(
    x = factor(type, levels = t_pos),
    y = value,
    fill = factor(name, levels = positions),
    label = sprintf("%3.1f%%", value * 100)
  )) +
  geom_col() +
  geom_text(position = position_stack(0.5), size = 2.5) +
  scale_y_continuous(labels = scales::percent, expand = c(0, 0.01)) +
  facet_wrap(c("prog"), nrow = 1) +
  labs(fill = "Found By", x = "Subject", y = "% of Covered Mutations") +
  theme_bw() +
  theme(
    legend.position = "right",
    axis.title.x = element_blank(),
    strip.text = element_text(size = 7),
    # panel.background = element_blank(),
    # panel.grid.major = element_line(size = 0.5, linetype = 'solid', colour = 'black'),
  )
p
# ggsave(p, filename = "plot/fig/oracle-percentages-stacked-aflpp.pdf", device = "pdf", width = 8, height = 1.7)

p <- rejiggered %>%
  ggplot(aes(
    x = factor(type, levels = t_pos),
    y = value,
    fill = factor(name, levels = positions),
    label = sprintf("%3.1f%%", value * 100)
  )) +
  geom_col() +
  geom_text(position = position_stack(0.5), size = 3) +
  scale_y_continuous(labels = scales::percent, expand = c(0, 0.04)) +
  facet_grid(c("fuzzer", "prog")) +
  labs(fill = "Found By", x = "Subject", y = "Percentage of Covered Mutations that are Killed") +
  theme_bw() +
  theme(legend.position = "bottom", axis.title.x = element_blank())
p
# ggsave(p, filename = "plot/fig/oracle-percentages-stacked-full.pdf", device = "pdf", width = 8, height = 6)


p <- rejiggered %>%
  filter(fuzzer != "afl") %>%
  ggplot(aes(
    x = factor(type, levels = t_pos),
    y = value,
    fill = factor(name, levels = positions),
    label = sprintf("%3.1f%%", value * 100)
  )) +
  geom_col() +
  geom_text(position = position_stack(0.5), size = 3) +
  scale_y_continuous(labels = scales::percent, expand = c(0, 0)) +
  facet_grid(c("fuzzer", "prog")) +
  labs(fill = "Found By", x = "Subject", y = "Percentage of Covered Mutations that are Killed") +
  theme_bw() +
  theme(legend.position = "bottom", axis.title.x = element_blank(), strip.text = element_text(size = 6.5))
p
ggsave(p, filename = "plot/fig/oracle-percentages-stacked-no-afl.pdf", device = "pdf", width = 8, height = 4)
