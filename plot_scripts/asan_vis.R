source("plot_scripts/setup.R")

data = read.csv("plot/tmp_data/def_asan_results.csv")

res = data %>%
  select(prog, fuzzer, found___both, found__asan, found__def, covered___both, covered__asan, covered__def) %>%
  mutate(covered_cnt=(covered___both + covered__asan + covered__def)) %>%
  mutate(found_both_per=found___both / covered_cnt) %>%
  mutate(found_asan_per=found__asan / covered_cnt) %>%
  mutate(found_def_per=found__def / covered_cnt) %>%
  # mutate(covered_per=1 - found_both_per - found_asan_per - found_def_per) %>%
  select(-covered___both, -covered__asan, -covered_cnt, -covered__def) %>%
  rename(both = found_both_per, asan = found_asan_per, default = found_def_per) %>%
  pivot_longer(cols = c(both, asan, default)) %>%
  select(-found___both, -found__asan, -found__def)

res

asan <- res[res$name %in% c('both', 'asan'), ]
asan$type <- 'asan'
def <- res[res$name %in% c('both', 'default'), ]
def$type <- 'default'

rejiggered <- merge(def, asan, all=TRUE)

rejiggered

t_pos <- c('default', 'asan')
positions <- c("asan", "default", "both")

p <- rejiggered %>%
  filter(fuzzer == "aflpp") %>%
  ggplot(aes(x=factor(type, levels=t_pos))) +
  geom_col(aes(fill=factor(name, levels=positions), y=value)) +
  scale_y_continuous(labels = scales::percent, expand = c(0, 0)) +
  facet_wrap(c('prog')) +
  labs(fill='Found By', x="Subject", y="Percentage of Covered Mutations") +
  theme(legend.position="top", axis.title.x=element_blank())
p
ggsave(p, filename="plot/fig/oracle-percentages-aflpp.pdf", device="pdf", width=4, height=4)

p <- rejiggered %>%
  ggplot(aes(x=factor(type, levels=t_pos))) +
  geom_col(aes(fill=factor(name, levels=positions), y=value)) +
  scale_y_continuous(labels = scales::percent, expand = c(0, 0)) +
  facet_grid(c('prog', 'fuzzer')) +
  labs(fill='Found By', x="Subject", y="Percentage of Covered Mutations") +
  theme(legend.position="top", axis.title.x=element_blank())
p
ggsave(p, filename="plot/fig/oracle-percentages-full.pdf", device="pdf", width=4, height=8)



