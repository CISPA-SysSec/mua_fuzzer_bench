TOTAL_FUZZER = 'combined'
ALL_PROG = 'all'

def header():
    import altair as alt
    alt.data_transformers.disable_max_rows()

    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Mutation testing eval</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
        <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.2.0/jquery.min.js"></script>
        <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>

        <script src="https://cdn.jsdelivr.net/npm/vega@{vega_version}"></script>
        <script src="https://cdn.jsdelivr.net/npm/vega-lite@{vegalite_version}"></script>
        <script src="https://cdn.jsdelivr.net/npm/vega-embed@{vegaembed_version}"></script>
    <style>
    body {{
        margin-left:10px
    }}
    table {{
        border-collapse: collapse;
    }}
    th, td {{
        text-align: left;
        padding: 7px;
        border: none;
    }}
        tr:nth-child(even){{background-color: lightgray}}
    th {{
    }}
    </style>
    </head>
    <body>\n""".format(
        vega_version=alt.VEGA_VERSION,
        vegalite_version=alt.VEGALITE_VERSION,
        vegaembed_version=alt.VEGAEMBED_VERSION,
    )

def error_stats(con):
    import pandas as pd

    crashes = pd.read_sql_query("""
        select *
        from crashed_runs_summary
    """, con)
    res = ""
    if len(crashes) > 0:
        logger.info("Crashed runs:")
        logger.info(crashes)
        res += "<h2>Crashes</h2>"
        res += crashes.to_html()

    crashes = pd.read_sql_query("""
        select *
        from base_bin_crashes
    """, con)
    res = ""
    if len(crashes) > 0:
        logger.info("Base bin crashes:")
        logger.info(crashes)
        res += "<h2>Base Bin Crashes</h2>"
        res += crashes.to_html()

    crashes = pd.read_sql_query("""
        select *
        from not_covered_but_found
    """, con)
    res = ""
    if len(crashes) > 0:
        logger.info("Not Covered but Found:")
        logger.info(crashes)
        res += "<h2>Not Covered but Found</h2>"
        res += crashes.to_html()

    crashes = pd.read_sql_query("""
        select *
        from covered_by_seed_but_not_fuzzer
    """, con)
    res = ""
    if len(crashes) > 0:
        logger.info("Covered By Seed but Not Fuzzer:")
        logger.info(crashes)
        res += "<h2>Covered By Seed but Not Fuzzer</h2>"
        res += crashes.to_html()
    return res

def fuzzer_stats(con):
    import pandas as pd
    stats = pd.read_sql_query("SELECT * from run_results_by_fuzzer", con)
    logger.info(stats)
    # logger.info(stats[['fuzzer', 'total', 'done', 'found', 'f_by_f', 'avg_run_min', 'cpu_days']].to_latex())
    res = "<h2>Fuzzer Stats</h2>"
    res += stats.to_html()
    return res

def fuzzer_prog_stats(con):
    import pandas as pd
    stats = pd.read_sql_query("SELECT * from run_results_by_prog_and_fuzzer", con)
    logger.info(stats)
    # logger.info(stats[['fuzzer', 'total', 'done', 'found', 'f_by_f', 'avg_run_min', 'cpu_days']].to_latex())
    res = "<h2>Fuzzer by Program Stats</h2>"
    res += stats.to_html()
    return res

def mut_stats(con):
    import pandas as pd
    stats = pd.read_sql_query("SELECT * from run_results_by_mut_type", con)
    res = "<h2>Mutation Stats</h2>"
    res += stats.to_html()
    return res

def prog_stats(con):
    import pandas as pd
    stats = pd.read_sql_query("SELECT * from run_results_by_prog", con)
    res = "<h2>Program Stats</h2>"
    res += stats.to_html()
    return res

def latex_stats_seeds(seed_dir, run_results, out_dir):
    seed_dir = Path(seed_dir)
    seed_res = {}
    for rr in run_results[['exec_id', 'prog', 'fuzzer', 'mut_id', 'covered_by_seed', 'found_by_seed']
        ].groupby(['exec_id', 'prog', 'fuzzer']
        )['covered_by_seed', 'found_by_seed'].sum().iterrows():
        index = (rr[0][1], rr[0][2])
        cov = rr[1]['covered_by_seed']
        found = rr[1]['found_by_seed']
        seed_res[index] = (cov, found)

    run_data = []
    for res_json in seed_dir.glob("info_*.json"):
        with open(res_json, 'rt') as f:
            run_data.extend(json.load(f))

    bucketed = defaultdict(list)
    for dd in run_data:
        bucketed[(dd['prog'], dd['fuzzer'])].append(dd)

    data = defaultdict(lambda: defaultdict(dict))
    for _, bb in bucketed.items():
        sorted_bb = sorted(bb, key=lambda x: len(x['covered_mutations']))
        median_bb = sorted_bb[len(sorted_bb)//2]
        bb = median_bb
        data[bb['prog']][bb['fuzzer']] = median_bb

    all_progs = sorted(set(data.keys()))
    all_fuzzers = sorted(set(kk for dd in data.values() for kk in dd.keys()))
    
    res_table = ""

    all_fuzzers_str = ' & '.join(all_fuzzers)
    res_table += rf"Program &   \#Type &&   {all_fuzzers_str} \\" + "\n"
    res_table += r"\midrule" + "\n"

    for ii, pp in enumerate(all_progs):
        f_line = rf"\multirow{{4}}{{*}}{{{pp}}} & F: &"
        m_line = rf"                     & M: &"
        k_line = rf"                     & K: &"
        l_line = rf"                     & L: &"

        for ff in all_fuzzers:
            fuzzer_res = data[pp][ff]
            covered_mutations = len(fuzzer_res['covered_mutations'])
            covered_lines = len(set(tuple(ll) for ll in fuzzer_res['kcov_res']['covered_lines']))
            num_seeds = fuzzer_res['num_seeds_minimized']
            f_line += f" & {num_seeds}"
            m_line += f" & {covered_mutations} / {seed_res[(pp, ff)][0]}"
            k_line += f" & {seed_res[(pp, ff)][1]}"
            l_line += f" & {covered_lines}"

        # max_num_mutations = "---"
        # max_num_lines = "---"
        # f_line += rf" & & \\"
        # m_line += rf" & & {max_num_mutations} \\"
        # l_line += rf" & & {max_num_lines} \\"

        f_line += rf" \\"
        m_line += rf" \\"
        k_line += rf" \\"
        l_line += rf" \\"
        res_table += f_line + "\n"
        res_table += m_line + "\n"
        res_table += k_line + "\n"
        res_table += l_line + "\n"
        if ii < len(all_progs) - 1:
            res_table += r"\cmidrule{4-7}" + "\n"

    with open(out_dir/"seed-stats.tex", "wt") as f:
        f.write(res_table)


def latex_stats(out_dir, con):
    # def value_to_file(stats, name, path):
    #     print(name)
    #     print(stats[name])
    #     val = stats[name].unique()
    #     print(val)
    #     assert len(val) == 1
    #     val = val[0]
    #     path = path.with_stem(path.stem + "---" + name.replace('_', '-'))
    #     with open(path, 'w') as f:
    #         f.write(str(val))

    # def write_table(latex, path):
    #     latex = re.sub(r'\\(toprule|midrule|bottomrule)$', r'\\hline', latex, flags=re.M)
    #     with open(path, 'w') as f:
    #         f.write(latex)

    import pandas as pd
    logger.info(f"Writing latex tables to: {out_dir}")

    old_float_format = pd.options.display.float_format
    pd.options.display.float_format = lambda x : '{:.0f}'.format(x) if round(x,0) == x else '{:,.2f}'.format(x)

    stats = pd.read_sql_query("SELECT * from run_results_by_fuzzer", con)
    stats = stats[['fuzzer', 'done', 'covered', 'c_by_f', 'found', 'f_by_f']]
    stats.rename(columns={'done': 'total', 'c_by_f': 'dyn cov', 'f_by_f': 'dyn found'}, inplace=True)
    styler = stats.style
    styler.na_rep = '---'
    styler.hide(axis='index')
    styler.to_latex(buf=out_dir/"fuzzer-stats.tex")

    combined_total = len(pd.read_sql_query("""
        select 1 from run_results
        group by exec_id, prog, mut_id, run_ctr;
    """, con))

    combined_covered = len(pd.read_sql_query("""
        select 1 from run_results
        where covered_file_seen is not NULL
        group by exec_id, prog, mut_id, run_ctr;
    """, con))

    combined_confirmed = len(pd.read_sql_query("""
        select 1 from run_results
        where time_found is not NULL
        group by exec_id, prog, mut_id, run_ctr;
    """, con))

    stats = pd.concat([stats, pd.DataFrame.from_dict({
        'fuzzer': ['combined'],
        'total': [combined_total],
        'covered': [combined_covered],
        'dyn cov': [0],
        'found': [combined_confirmed],
        'dyn found': [0],
    })], ignore_index=True)

    stats.to_csv(path_or_buf=out_dir/"fuzzer-stats.csv")

    # stats = pd.read_sql_query("SELECT * from run_results_by_prog", con)
    # print(stats.columns)
    # stats = stats[['prog', 'done', 'covered', 'interesting', 'confirmed']]
    # stats.rename(columns={'done': 'total', 'interesting': 'stubborn', 'confirmed': 'killed'}, inplace=True)
    # styler = stats.style
    # styler.na_rep = '---'
    # styler.hide(axis='index')
    # styler.to_latex(buf=out_dir/"prog-stats.tex")
    # ,
    #     header=['prog', 'total', 'covered', 'by seed', 'stubborn', 'by one', 'by all'],
    #     na_rep='---',
    #     index=False,
    # )

    # stats = pd.read_sql_query("SELECT * from run_results_by_mut_type", con)
    # stats = stats[['name', 'done', 'covered', 'f_by_seed', 'interesting', 'f_by_one', 'f_by_all']]
    # stats.rename(columns={'name': 'mutation', 'done': 'total', 'f_by_f': 'by fuzzer'}, inplace=True)

    # .to_latex(
    #     buf=out_dir/"mut-type-stats.tex",
    #     header=['mutation', 'total', 'covered', 'by seed', 'stubborn', 'by one', 'by all'],
    #     na_rep='---',
    #     index=False,
    # )
    # styler = stats.style
    # styler.na_rep = '---'
    # styler.hide(axis='index')

    stats = pd.read_sql_query("SELECT * from run_results_by_prog_and_fuzzer", con)
    stats = stats[['prog', 'fuzzer', 'done', 'covered', 'c_by_f', 'found', 'f_by_f']]
    stats.rename(columns={'done': 'total', 'c_by_f': 'by fuzzer', 'f_by_f': 'by fuzzer'}, inplace=True)
    styler = stats.style
    styler.na_rep = '---'
    styler.hide(axis='index')
    styler.to_latex(buf=out_dir/"prog-fuzzer-stats.tex")

    stats.to_csv(path_or_buf=out_dir/"prog-fuzzer-stats.csv")

    stats = pd.read_sql_query("SELECT prog, mutations, supermutants, reduction from reduction_per_prog", con)
    stats = stats[['prog', 'mutations', 'supermutants', 'reduction']]
    # stats.rename(columns={'done': 'total', 'c_by_f': 'by fuzzer', 'f_by_f': 'by fuzzer'}, inplace=True)
    styler = stats.style
    styler.format(precision=2)
    styler.na_rep = '---'
    styler.hide(axis='index')
    styler.to_latex(buf=out_dir/"reduction-prog.tex")

    stats.to_csv(path_or_buf=out_dir/"reduction-prog.csv")

    old_max_with = pd.get_option('display.max_colwidth')
    pd.set_option('display.max_colwidth', 1000)

    stats = pd.read_sql_query("SELECT * from mutation_types group by mut_type", con)
    stats = stats[['pattern_name', 'description', 'procedure']]
    stats['pattern_name'] = stats['pattern_name'].transform(lambda x: x.replace('_', ' '))
    # stats.rename(columns={'pattern_name': 'mutation'}, inplace=True)
    styler = stats.style
    styler.na_rep = '---'
    styler.hide(axis='index')
    styler.format(escape='latex')
    styler.to_latex(
        column_format="p{.18\\textwidth}p{.4\\textwidth}p{.4\\textwidth}",
        buf=out_dir/"mutations.tex",
        environment='longtable',
        # longtable=True,
        # multirow_=True,
    )

    stats.to_csv(path_or_buf=out_dir/"mutations.csv")

        # header=['mutation', 'description', 'procedure'],
        # na_rep='---',
        # index=False,
        # column_format="p{.18\\textwidth}p{.4\\textwidth}p{.4\\textwidth}",

    pd.options.display.float_format = old_float_format
    pd.set_option('display.max_colwidth', old_max_with)

def aflpp_stats(con):
    import pandas as pd
    stats = pd.read_sql_query("SELECT * from aflpp_runtime_stats", con)
    res = "<h2>AFL style fuzzers -- Stats</h2>"
    res += stats.to_html()
    return res

def plot(plot_dir, title, mut_type, data, num_mutations, absolute):
    import inspect
    import types
    from typing import cast
    import altair as alt
    alt.data_transformers.disable_max_rows()
    all_fuzzers = set(run.fuzzer for run in data.itertuples())
    func_name = cast(types.FrameType, inspect.currentframe()).f_code.co_name
    selection = alt.selection_multi(fields=['fuzzer', 'prog'], bind='legend',
        init=[{'fuzzer': fuzzer, 'prog': ALL_PROG} for fuzzer in all_fuzzers])
    color = alt.condition(selection,
                      alt.Color('fuzzer:O', legend=None),
                      alt.value('lightgray'))
    base = alt.Chart(data)

    if absolute:
        plot = base.mark_line(
            interpolate='step-after',
        ).encode(
            alt.Y('value', title="Killed Mutants"),
            x=alt.X('time', title="Time (Minutes)"), #, scale=alt.Scale(type='symlog')),
            color='fuzzer',
            tooltip=['time', 'confirmed', 'value', 'covered', 'total', 'fuzzer', 'prog'],
        )
        plot = plot.mark_point(size=5, opacity=1, tooltip=alt.TooltipContent("encoding")) + plot
        #  plot2 = base.mark_line(strokeDash=[4,2]).encode(
        #      y=alt.Y('total', title="Killed Mutants"),
        #      x=alt.X('time', title="Time (Minutes)"), #, scale=alt.Scale(type='symlog')),
        #      color='fuzzer',
        #      tooltip=['time', 'confirmed', 'value', 'covered', 'total', 'fuzzer', 'prog'])
        #  plot = plot + plot2
    else:
        plot = base.mark_line(
            interpolate='step-after',
        ).encode(
            x=alt.X('time', title="Time (Minutes)"), #, scale=alt.Scale(type='symlog')),
            y=alt.Y('value', title="Percentage Killed Mutants"),
            color='fuzzer',
            tooltip=['time', 'confirmed', 'value', 'covered', 'total', 'fuzzer', 'prog'])
        plot = plot.mark_point(size=5, opacity=1, tooltip=alt.TooltipContent("encoding")) + plot
    plot = plot.properties(
        title=title,
        width=600,
        height=400,
    )

    plot = plot.add_selection(
        alt.selection_interval(bind='scales', encodings=['x'])
    ).transform_filter(
        selection
    )

    counts = [f"{prog}: {val[0]} / {val[1]}" for prog, val in num_mutations.items()]

    all_selection = alt.Chart(data).mark_rect().encode(
        x=alt.X('prog', axis=alt.Axis(orient='bottom')),
        y=alt.Y('fuzzer', axis=alt.Axis(orient='right')),
        color=color
    ).properties(
        title=alt.TitleParams(
            ['', '#Analyzed Mutations:'] + counts,
            baseline='top',
            orient='bottom',
            anchor='end',
            fontWeight='normal',
            fontSize=10
        )
    )

    plot = (plot | all_selection).add_selection(
        selection
    )
    slug_title = title.replace(" ", "").replace(":", "")
    res = f'<div id="{slug_title}{func_name}{mut_type}"></div>'
    res += '''<script type="text/javascript">
                vegaEmbed('#{slug_title}{func_name}{mut_id}', {spec1}).catch(console.error);
              </script>'''.format(slug_title=slug_title, func_name=func_name, mut_id=mut_type,
                                  spec1=plot.to_json(indent=None))
    if plot_dir is not None:
        import matplotlib.pyplot as plt
        from matplotlib import ticker
        import seaborn
        import numpy as np

        seaborn.set(style='ticks')

        fuzzers = data.fuzzer.unique()
        values = { ff: [] for ff in fuzzers }
        for row in data.itertuples():
            if row.prog != 'all':
                continue
            values[row.fuzzer].append((row.time, row.value))

        fig, ax = plt.subplots()
        ax.set_title(title)
        ax.set_xlabel('Time in Minutes')
        # ax.set_xscale('log')
        ax.xaxis.set_major_formatter(ticker.ScalarFormatter())
        ax.set_ylabel('Killed Mutants' if absolute else 'Killed Mutants %')
        ax.grid(True, which='both')
        plot_handles = []
        for ff, vals in values.items():
            x, y = list(zip(*vals))
            handle, = ax.plot(x, y, label=ff)
            plot_handles.append(handle)
        ax.legend(handles=plot_handles, bbox_to_anchor=(0.5, -0.2), loc='upper center', ncol=3)
        # fig.subplots_adjust(top=1-tt, bottom=0.25, wspace=0.2)
        fig.tight_layout()
        seaborn.despine(ax=ax)

        plot_path_svg = plot_dir.joinpath(f"{slug_title}.svg")
        plot_path_pdf = plot_path_svg.with_suffix(".pdf")
        fig.savefig(plot_path_pdf, format="pdf")
        plt.close(fig)
    return res

def split_vals(val):
    if val is None:
        return []
    return [float(v) for v in val.split("/////")]

def gather_plot_data(runs, run_results):
    from collections import defaultdict
    import pandas as pd

    if len(run_results) == 0:
        return None

    max_time = 0
    all_progs = set(run.prog for run in runs.itertuples())
    all_fuzzers = set(run.fuzzer for run in runs.itertuples())

    absolute_num_mutations = defaultdict(lambda: [0, 0])

    print(runs.head())
    print(run_results.head())

    for run in runs.itertuples():
        if run.fuzzer != list(all_fuzzers)[0]:
            continue
        absolute_num_mutations[run.prog][1] += run.total
        absolute_num_mutations[ALL_PROG][1] += run.total

    cnt_prog_runs = defaultdict(set)
    cnt_fuzzer_runs = defaultdict(set)
    cnt_fuzzer_prog_runs = defaultdict(set)
    cnt_runs = set()

    for event in run_results.itertuples():
        cnt_prog_runs[event.prog].add(event.mut_id)
        cnt_fuzzer_runs[event.fuzzer].add((event.prog, event.mut_id))
        cnt_fuzzer_prog_runs[(event.fuzzer, event.prog)].add(event.mut_id)
        cnt_runs.add((event.prog, event.mut_id))

    total_runs = defaultdict(lambda: 0)
    for prog, max_total in cnt_prog_runs.items():
        total_runs[(TOTAL_FUZZER, prog)] = len(max_total)
        absolute_num_mutations[prog][0] = len(max_total)
    for fuzzer, max_total in cnt_fuzzer_runs.items():
        total_runs[(fuzzer, ALL_PROG)] = len(max_total)
    for (fuzzer, prog), max_total in cnt_fuzzer_prog_runs.items():
        total_runs[(fuzzer, prog)] = len(max_total)
    total_runs[(TOTAL_FUZZER, ALL_PROG)] = len(cnt_runs)
    absolute_num_mutations[ALL_PROG][0] = len(cnt_runs)

    data = defaultdict(list)
    unique_events = []

    for event in run_results.itertuples():
        import math
        if event.covered_file_seen is None or math.isnan(event.covered_file_seen):
            continue
        unique_events.append({
            'fuzzer': event.fuzzer,
            'prog': event.prog,
            'id': event.mut_id,
            'type': 'covered',
            'stage': 'initial' if event.covered_by_seed else event.stage,
            'time': event.covered_file_seen,
        })

    for event in run_results.itertuples():
        if event.confirmed != 1:
            continue
        # if event.found_by_seed:
        #     continue
        unique_events.append({
            'fuzzer': event.fuzzer,
            'prog': event.prog,
            'id': event.mut_id,
            'type': 'confirmed',
            'stage': event.stage,
            'time': event.time_found,
        })

    counter = defaultdict(lambda: {
        'covered': 0,
        'confirmed': 0,
    })

    totals_set = defaultdict(set)

    def inc_counter(fuzzer, prog, id, counter_type):
        counter[(fuzzer, prog)][counter_type] += 1
        counter[(fuzzer, ALL_PROG)][counter_type] += 1
        if id not in totals_set[(prog, counter_type)]:
            totals_set[(prog, counter_type)].add(id)
            counter[(TOTAL_FUZZER, prog)][counter_type] += 1
            counter[(TOTAL_FUZZER, ALL_PROG)][counter_type] += 1
            return True
        return False

    def add_datapoint(fuzzer, prog, time):
        counts = counter[(fuzzer, prog)]
        total = total_runs[(fuzzer, prog)]
        try:
            total_percentage = (counts['confirmed'] / total) * 100
        except ZeroDivisionError:
            print("zero")
            total_percentage = 0

        try:
            confirmed_percentage = (counts['confirmed'] / counts['covered']) * 100
        except ZeroDivisionError:
            print("bug not covered but confirmed")
            confirmed_percentage = 0

        absolute = counts['confirmed']

        for name, val in [
                ('total', total_percentage),
                ('covered', confirmed_percentage),
                ('absolute', absolute),
        ]:
            data[name].append({
                'fuzzer': fuzzer,
                'prog': prog,
                'time': time,
                'confirmed': counts['confirmed'],
                'covered': counts['covered'],
                'total': total,
                'value': val,
            })

    for event in unique_events:
        if event['stage'] == 'initial':
            inc_counter(event['fuzzer'], event['prog'], event['id'], event['type'])

    # add initial points
    for run in runs.itertuples():
        add_datapoint(run.fuzzer, run.prog, 0)
    for fuzzer in all_fuzzers:
        add_datapoint(fuzzer, ALL_PROG, 0)
    for prog in all_progs:
        add_datapoint(TOTAL_FUZZER, prog, 0)
    add_datapoint(TOTAL_FUZZER, ALL_PROG, 0)

    # add the data points
    for event in sorted(unique_events, key=lambda x: x['time']):
        if event['stage'] == 'initial':
            continue

        if event['time'] > max_time:
            max_time = event['time']

        total_inc: bool = inc_counter(event['fuzzer'], event['prog'], event['id'], event['type'])
        add_datapoint(event['fuzzer'], event['prog'], event['time'])
        add_datapoint(event['fuzzer'], ALL_PROG, event['time'])
        if total_inc:
            add_datapoint(TOTAL_FUZZER, event['prog'], event['time'])
            add_datapoint(TOTAL_FUZZER, ALL_PROG, event['time'])

    # add final points
    for fuzzer, prog in counter.keys():
        add_datapoint(fuzzer, prog, max_time)

    return {
        'num_mutations': absolute_num_mutations,
        'total': pd.DataFrame(data['total']),
        'covered': pd.DataFrame(data['covered']),
        'absolute': pd.DataFrame(data['absolute']),
    }

def matrix_unique_finds(unique_finds):
    from collections import defaultdict
    import pandas as pd
    import numpy as np

    matrix = defaultdict(dict)
    for row in unique_finds.itertuples():
        matrix[row.other_fuzzer][row.fuzzer] = row.finds

    matrix = pd.DataFrame(matrix).fillna(-1).astype(int).replace({-1: ""})
    matrix = matrix.reindex(sorted(matrix.columns), axis=0)
    matrix = matrix.reindex(sorted(matrix.columns), axis=1)

    return matrix

def create_mut_type_plot(plot_dir, mut_type, runs, run_results, unique_finds, mutation_info):
    plot_data = gather_plot_data(runs, run_results)

    # logger.info(mutation_info)
    pattern_name = mutation_info['pattern_name'].iat[0]
    pattern_class = mutation_info['pattern_class'].iat[0]
    description = mutation_info['description'].iat[0]
    procedure = mutation_info['procedure'].iat[0]

    res = f'<h3>Mutation {mut_type}: {pattern_name}</h3>'
    res += f'<p>Class: {pattern_class}</p>'
    res += f'<p>Description: {description}</p>'
    res += f'<p>Procedure: {procedure}</p>'
    res += '<h4>Overview</h4>'
    res += runs.to_html()
    if plot_data is not None:
        res += plot(None, f"Killed Covered Mutants of type: {mut_type}", mut_type, plot_data['covered'], plot_data['num_mutations'], False)
        res += plot(None, f"Killed Mutants of type: {mut_type}", mut_type, plot_data['total'], plot_data['num_mutations'], False)
        res += plot(None, f"Absolute Killed Mutants of type: {mut_type}", mut_type, plot_data['absolute'], plot_data['num_mutations'], True)
    res += '<h4>Unique Finds</h4>'
    res += 'Left finds what upper does not.'
    res += matrix_unique_finds(unique_finds).to_html(na_rep="")
    return res

def footer():
    return """
    </body>
    </html>
    """

def wayne_diagram(values, total_sum, fuzzers, plot_pdf_path):
    import matplotlib.pyplot as plt
    import matplotlib.patches as patches

    fig, ax = plt.subplots()

    ax.set_title("Overlap of Killed Mutants between Fuzzers")
    ax.set_axis_off()
    ax.set_xlim([.78, 2.1])
    ax.set_ylim([0, 1.06])

    def ell(offset, angle, color):
        return patches.Ellipse(offset, 1, 0.5, angle=angle, alpha=.3, color=color)

    cmap = plt.get_cmap('Set1')

    ax.add_patch(ell((1.1825, .4), 90+45, color=cmap.colors[0]))
    ax.text(0.85, .84, fuzzers[0], color=cmap.colors[0], alpha=.7)

    ax.add_patch(ell((1.425, .52), 90+45, color=cmap.colors[1]))
    ax.text(1.1, .96, fuzzers[1], color=cmap.colors[1], alpha=.7)

    ax.add_patch(ell((1.425, .52), 90-45, color=cmap.colors[2]))
    ax.text(1.6, .96, fuzzers[2], color=cmap.colors[2], alpha=.7)

    ax.add_patch(ell((1.6675, .4), 90-45, color=cmap.colors[3]))
    ax.text(1.85, .84, fuzzers[3], color=cmap.colors[3], alpha=.7)


    texts = {
        '1___': (None, (0.9, .48)),
        '_2__': (None, (1.2, .77)),
        '__3_': (None, (1.56, .77)),
        '___4': (None, (1.85, .48)),
        '12__': (None, (1.07, .62)),
        '1_3_': (None, (1.1, .25)),
        '1__4': (None, (1.375, .07)),
        '_23_': (None, (1.375, .64)),
        '_2_4': (None, (1.65, .25)),
        '__34': (None, (1.69, .62)),
        '_234': (None, (1.55, .48)),
        '1_34': (None, (1.28, .18)),
        '12_4': (None, (1.48, .18)),
        '123_': (None, (1.2, .48)),
        '1234': (None, (1.375, .32)),
    }

    texts = {kk: (values[kk], (vv[1][0], vv[1][1])) for kk, vv in texts.items()}

    for tt in texts.values():
        ax.text(tt[1][0], tt[1][1], tt[0])

    ax.text(.8, .01, f"Total Killed: {total_sum}")

    # note that text is not scaled
    scaling = 1.4
    fig.set_size_inches(scaling*7, scaling*4)

    fig.savefig(plot_pdf_path, format="pdf")
    plt.close(fig)


def plot_killed_union(runs, run_results, plot_dir):
    from itertools import combinations
    all_fuzzers = sorted(runs.fuzzer.unique())
    if len(all_fuzzers) != 4:
        logger.info(f"Results are contain not exactly 4 fuzzers ({all_fuzzers}), skipping wayne diagram.")
        return

    found = run_results[run_results['confirmed'].notnull()]

    fuzzers_found_mutation = defaultdict(list)
    for _, ff in found.iterrows():
        fuzzers_found_mutation[(ff['exec_id'], ff['prog'], ff['mut_id'])].append(ff['fuzzer'])


    # Separate buckets
    values = {
        '1___': 0,
        '_2__': 0,
        '__3_': 0,
        '___4': 0,
        '12__': 0,
        '1_3_': 0,
        '1__4': 0,
        '_23_': 0,
        '_2_4': 0,
        '__34': 0,
        '_234': 0,
        '1_34': 0,
        '12_4': 0,
        '123_': 0,
        '1234': 0,
    }

    total_sum = 0
    for ff in fuzzers_found_mutation.values():
        # Count each bucket separately
        key = ""
        for ii, fuzzer in enumerate(all_fuzzers):
            if fuzzer in ff:
                key += f"{ii+1}"
            else:
                key += "_"
        values[key] += 1

        total_sum += 1

    values = {kk: f"{vv}\n[{(100*vv/total_sum):.1f}%]" for kk, vv in values.items()}
    
    plot_path_pdf = plot_dir.joinpath(f"wayne-diagram-separate.pdf")
    wayne_diagram(values, total_sum, all_fuzzers, plot_path_pdf)


def plot_mutation_distribution(con, plot_dir):
    import pandas as pd
    import matplotlib.pyplot as plt
    from matplotlib.sankey import Sankey

    plt.set_loglevel('info')

    # total_num = 102677
    total_num = int(pd.read_sql_query("select count() as cnt from union_run_results", con)['cnt'][0])

    covered_num = int(pd.read_sql_query("select count() as cnt from union_run_results_covered", con)['cnt'][0])
    not_covered = (total_num - covered_num) / total_num
    # not_covered = 19970 / total_num


    killed_by_seed_num = int(pd.read_sql_query("select count() as cnt from union_run_results_found", con)['cnt'][0])
    killed_by_seed = killed_by_seed_num / total_num

    stubborn = (1 - not_covered - killed_by_seed)

    total_manual = 100
    immortal = 75 / total_manual * stubborn
    equivalent = 16 / total_manual * stubborn
    sanitizer = 6 / total_manual * stubborn
    difficult = 3 / total_manual * stubborn

    fig, ax = plt.subplots()
    ax.set_axis_off()
    # ax = fig.add_subplot(1, 1, 1, xticks=[], yticks=[], title="Distribution of mutations")

    sankey = Sankey(ax=ax, format="%.02f", unit="%", scale=.01)
    sankey.add(
        flows=[vv*100 for vv in [1, -not_covered, -killed_by_seed, -stubborn]],
        labels=['Mutations', 'Not Covered', 'Killed By Seed', 'Stubborn'],
        orientations=[0, 1, -1, 0],
    )

    sankey.add(
        prior=0,
        connect=(3, 0),
        flows=[vv*100 for vv in [stubborn, -immortal, -equivalent, -sanitizer, -difficult]],
        labels=[None, 'Immortal (Oracle too Weak)', 'Equivalent', 'Sanitizer', 'Difficult'],
        orientations=[0, 1, 1, 0, -1],
        pathlengths=[.0, .25, .25, .15, .25]
    )

    sankey.finish()
    fig.savefig(plot_dir.joinpath("mutation-distribution.pdf"), format="pdf")
    plt.close(fig)
    

def generate_plots(db_path, seed_dir, to_disk, skip_script):
    import pandas as pd
    db_path = Path(db_path)

    plot_dir = db_path.parent/"plots"
    if to_disk:
        shutil.rmtree(plot_dir, ignore_errors=True)
        plot_dir.mkdir(parents=True, exist_ok=True)

    con = sqlite3.connect(db_path)
    con.isolation_level = None
    con.row_factory = sqlite3.Row

    if not skip_script:
        logger.info("Executing eval.sql script...")
        with open("eval.sql", "rt") as f:
            cur = con.cursor()
            cur.executescript(f.read())
        logger.info("done")

    res = header()
    # logger.info("crashes")
    # res += error_stats(con)
    # logger.info("fuzzer stats")
    # res += fuzzer_stats(con)
    # logger.info("fuzzer prog stats")
    # res += fuzzer_prog_stats(con)
    # logger.info("mut stats")
    # res += mut_stats(con)
    # logger.info("prog stats")
    # res += prog_stats(con)
    # logger.info("afl stats")
    # res += aflpp_stats(con)

    # logger.info("select mut_types")
    # mut_types = pd.read_sql_query("SELECT * from mut_types", con)
    logger.info("select runs")
    runs = pd.read_sql_query("select * from run_results_by_mut_type_and_fuzzer", con)
    logger.info("select run_results")
    run_results = pd.read_sql_query("select * from run_results", con)
    # logger.info("select unique_finds")
    # unique_finds = pd.read_sql_query("select * from unique_finds", con)
    # #  logger.info("select unique_finds_overall")
    # #  unique_finds_overall = pd.read_sql_query("select * from unique_finds_overall", con)
    # logger.info("select mutation_types")
    # mutation_info = pd.read_sql_query("select * from mutation_types", con)

    # res += "<h2>Plots</h2>"
    # res += "<h3>Overall Plots</h3>"
    # logger.info("overall")
    total_plot_data = gather_plot_data(runs, run_results)
    if total_plot_data is not None:
        res += plot(plot_dir if to_disk else None, f"Killed Covered Mutants Overall", "overall", total_plot_data['covered'], total_plot_data['num_mutations'], False)
        res += plot(plot_dir if to_disk else None, f"Killed Mutants Overall", "overall", total_plot_data['total'], total_plot_data['num_mutations'], False)
        res += plot(plot_dir if to_disk else None, f"Absolute Killed Mutants Overall", "overall", total_plot_data['absolute'], total_plot_data['num_mutations'], True)

    if to_disk:
        latex_stats(plot_dir, con)
        plot_killed_union(runs, run_results, plot_dir)
        if seed_dir is not None:
            latex_stats_seeds(seed_dir, run_results, plot_dir)
        plot_mutation_distribution(con, plot_dir)
    #  res += '<h4>Unique Finds</h4>'
    #  res += 'Left finds what upper does not.'
    #  res += matrix_unique_finds(unique_finds_overall).to_html(na_rep="")

    # for mut_type in mut_types['mut_type']:
    #     logger.info(mut_type)
    #     res += create_mut_type_plot(plot_dir, mut_type,
    #         runs[runs.mut_type == mut_type],
    #         run_results[run_results.mut_type == mut_type],
    #         unique_finds[unique_finds.mut_type == mut_type],
    #         mutation_info[mutation_info.mut_type == mut_type],
    #     )
    # res += footer()

    # out_path = db_path.with_suffix(".html").resolve()
    # logger.info(f"Writing plots to: {out_path}")
    # with open(out_path, 'w') as f:
    #     f.write(res)
    # logger.info(f"Open: file://{out_path}")