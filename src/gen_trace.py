#!/bin/python3
""" script that generate trace group info """
import sys
import yaml
import re

global_status = {}
global_names = {}
global_status['trace_index'] = 1

rule_levels = {
    'info': 'RULE_INFO',
    'warn': 'RULE_WARN',
    'error': 'RULE_ERROR',
}

rule_types = {
    'eq': 'RULE_RETURN_EQ',
    'lt': 'RULE_RETURN_LT',
    'gt': 'RULE_RETURN_GT',
    'ne': 'RULE_RETURN_NE',
    'range': 'RULE_RETURN_RANGE',
    'any': 'RULE_RETURN_ANY',
}


def parse_names(trace, children):
    children.remove(trace)
    names = trace['names']
    del trace['names']

    for name in names:
        if isinstance(name, str):
            name = {'name': name}

        tmp = dict(trace)
        tmp.update(name)
        name.update(tmp)
        if 'cond' in name:
            name['cond'] = name['cond'].replace('"', '\\"')

        children.append(name)


def parse_group(group):
    """ parse group in yaml file """
    if 'children' not in group:
        return
    children = group['children']
    i = 0
    while i < len(children):
        child = children[i]
        if 'backup' in child:
            child['backup']['is_backup'] = True

        if isinstance(child, str):
            children.remove(child)
            child = {
                "name": child
            }
            children.insert(i, child)

        parse_group(child)
        if 'names' in child:
            parse_names(child, children)
            continue
        i += 1
        if 'children' in child:
            continue

        name_split = child['name'].split(':')
        if len(name_split) > 1:
            child['skb'] = int(re.match(r'\d+', name_split[1]).group())
        name_split = child['name'].split('/')
        if len(name_split) > 1:
            child['sock'] = int(re.match(r'\d+', name_split[1]).group())
        child['name'] = re.match(r'[a-zA-Z_0-9]+', child['name']).group()


def gen_group_init(group, name):
    return f'''trace_group_t {name} = {{
	.name = "{group['name']}",
	.desc = "{group.get('desc')}",
	.children = LIST_HEAD_INIT({name}.children),
	.traces = LIST_HEAD_INIT({name}.traces),
	.list = LIST_HEAD_INIT({name}.list),
}};
'''


def gen_name(name, is_trace=False):
    if is_trace:
        name = name.replace('-', '_')
    else:
        name = ('group_' + name).replace('-', '_')
    if name in global_names:
        global_names[name] += 1
        return f'{name}_{global_names[name]}'
    global_names[name] = 0
    return name


btf_data = None


def get_arg_count(name):
    global btf_data
    if not btf_data:
        with open("btf.raw", 'r', encoding='utf-8') as btf_file:
            btf_data = btf_file.read()
    reg_text = f"'{name}' type_id=([0-9]+)"
    match = re.search(reg_text, btf_data)
    if not match:
        return 0

    type_id = match.group(1)
    match = re.search(f"\\[{type_id}\\].*vlen=([0-9]+)", btf_data)
    return match.group(1)


def gen_rules(rules, name):
    rule_str, init_str = '', ''
    for index, rule in enumerate(rules):
        level = rule['level']
        rule_tmp = f'\t.level = {rule_levels[level]},\n'
        exps = rule['exp'].split(' ')
        rule_type = rule_types[exps[0]]
        if exps[0] == 'range':
            ranges = exps[1].split('-')
            rule_tmp += f'\t.range = {{ .min = {ranges[0]}, .max = {ranges[1]}}},\n'
        elif exps[0] != 'any':
            rule_tmp += f'\t.expected = {exps[1]},\n'
        rule_tmp += f'\t.type = {rule_type},\n'
        if 'adv' in rule:
            rule_adv = rule["adv"].replace('\n', '\\n')
            rule_tmp += f'\t.adv = "{rule_adv}",\n'
        msg = f'PFMT_EMPH"{rule["msg"]}"PFMT_END'
        if level == 'warn':
            msg = f'PFMT_WARN"{rule["msg"]}"PFMT_END'
        elif level == 'error':
            msg = f'PFMT_ERROR"{rule["msg"]}"PFMT_END'
        rule_tmp += f'\t.msg = {msg},\n'
        rule_name = f'rule_{name}_{index}'
        rule_str += f'rule_t {rule_name} = {{{rule_tmp}}};\n'
        init_str += f'\tlist_add_tail(&{rule_name}.list, &{name}.rules);\n'
    return (rule_str, init_str)


def append_trace_field(field, trace, type='string'):
    if type == 'string':
        return f'\n\t.{field} = "{trace[field]}",' if field in trace else ''
    if type == 'bool':
        value = 'true' if trace.get(field) else 'false'
        return f'\n\t.{field} = {value},'
    if type == 'raw':
        if field in trace:
            return f'\n\t.{field} = {trace[field]},'
    return ''


def append_filed(field, value, type='string'):
    if type == 'string':
        return f'\n\t.{field} = "{value}",'
    if type == 'bool':
        value = 'true' if value else 'false'
        return f'\n\t.{field} = {value},'
    if type == 'raw':
        return f'\n\t.{field} = {value},'
    return ''


def gen_trace_list(trace, p_name):
    name = trace['define_name']
    list_count = trace.get('list_count', 1)
    list_count += 1
    trace['list_count'] = list_count
    trace_name = 'trace_' + name
    trace_list = f'{trace_name}_list_{list_count}'
    define_str = f'''
trace_list_t {trace_list} = {{
\t.trace = &{trace_name},
\t.list = LIST_HEAD_INIT({trace_list}.list)
}};
'''
    init_str = f'\tlist_add_tail(&{trace_list}.list, &{p_name}.traces);\n'

    return {
        'define_str': define_str,
        'init_str': init_str,
        'probe_str': '',
        'index_str': ''
    }


def gen_trace(trace, group, p_name):
    # trace is already defined, just define corresponding trace_list for it
    if 'define_name' in trace:
        return gen_trace_list(trace, p_name)

    name = gen_name(trace["name"], True)
    trace_name = 'trace_' + name
    trace['define_name'] = name
    probe_str = ''
    skb_str = ''
    index_str = f'#define INDEX_{name} {global_status["trace_index"]}\n'
    rule_str = ''
    init_str = ''
    fields_str = ''
    skb_index = 0
    sk_index = 0
    target = trace.get('target') or trace['name']

    if 'tp' in trace:
        trace_type = 'TRACE_TP'
        tp = trace['tp'].split(':')
        skb_str = f'\n\t.tp = "{trace["tp"]}",'
        if 'skb' in trace:
            probe_str = f'\tFN_tp({name}, {tp[0]}, {tp[1]}, {trace["skb"]})\t\\\n'
    else:
        trace_type = 'TRACE_FUNCTION'
        if 'skb' in trace or 'sock' in trace:
            arg_count = '0'
            if 'monitor' in trace:
                if 'arg_count' not in trace:
                    trace['arg_count'] = get_arg_count(target)
                    arg_count = trace['arg_count']
                else:
                    arg_count = trace['arg_count']
                if not arg_count:
                    print(
                        f"BTF not found for {target}, skip monitor", file=sys.stderr)
                    trace['monitor'] = 0
                else:
                    fields_str += append_trace_field('arg_count', trace, 'raw')
            if 'skb' in trace:
                skb_index = int(trace["skb"]) + 1
                skb_str = f'\n\t.skb = {skb_index},'
            if 'sock' in trace:
                sk_index = int(trace["sock"]) + 1
            if 'custom' not in trace:
                probe_str = f'\tFN({name}, {skb_index}, {sk_index}, {arg_count})\t\\\n'
            else:
                probe_str = f'\tFNC({name})\t\\\n'
        else:
            probe_str = f'\tFNC({name})\t\\\n'
    if 'analyzer' in trace:
        analyzer = f'\n\t.analyzer = &ANALYZER({trace["analyzer"]}),'
    else:
        analyzer = '\n\t.analyzer = &ANALYZER(default),'

    if 'rules' in trace and trace['rules']:
        rules = trace['rules']
        (rule_str, _init_str) = gen_rules(rules, trace_name)
        init_str += _init_str

    fields_str += append_trace_field('cond', trace)
    fields_str += append_trace_field('regex', trace)
    fields_str += append_trace_field('msg', trace)
    fields_str += append_trace_field('is_backup', trace, 'bool')
    fields_str += append_trace_field('probe', trace, 'bool')
    fields_str += append_trace_field('monitor', trace, 'raw')
    fields_str += append_filed('name', target)

    default = True
    if 'default' in trace:
        default = trace['default']
    elif 'default' in group:
        default = group['default']
    fields_str += append_filed('def', default, 'bool')

    define_str = f'''trace_t {trace_name} = {{
\t.desc = "{trace.get('desc') or ''}",{skb_str}
\t.type = {trace_type},{analyzer}{fields_str}
\t.index = INDEX_{name},
\t.prog = "__trace_{name}",
\t.parent = &{p_name},
\t.sk = {sk_index},
\t.rules = LIST_HEAD_INIT({trace_name}.rules),
}};
trace_list_t {trace_name}_list = {{
\t.trace = &{trace_name},
\t.list = LIST_HEAD_INIT({trace_name}_list.list)
}};
{rule_str}
'''

    init_str += f'''\tlist_add_tail(&{trace_name}_list.list, &{p_name}.traces);
\tall_traces[INDEX_{name}] = &{trace_name};
\tlist_add_tail(&{trace_name}.all, &trace_list);
'''
    global_status['trace_index'] += 1

    return {
        'define_str': define_str,
        'init_str': init_str,
        'probe_str': probe_str,
        'index_str': index_str
    }


def gen_append(target, source):
    target['define_str'] += source['define_str']
    target['init_str'] += source['init_str']
    target['probe_str'] += source['probe_str']
    target['index_str'] += source['index_str']


def gen_group(group, is_root=False):
    if 'children' not in group:
        return

    result = {
        "define_str": '',
        "init_str": '',
        "probe_str": '',
        "index_str": '',
    }

    if is_root:
        p_name = 'root_group'
        group['define_name'] = p_name
        result['define_str'] += gen_group_init(group, p_name)
    else:
        p_name = group['define_name']

    for child in group['children']:
        if 'children' in child:
            name = gen_name(child["name"])
            child['define_name'] = name
            result['define_str'] += gen_group_init(child, name)
            result['init_str'] += f'\tlist_add_tail(&{name}.list, &{p_name}.children);\n'
            gen_append(result, gen_group(child))
        else:
            gen_append(result, gen_trace(child, group, p_name))

    for child in group['children']:
        if 'children' in child:
            continue
        backup = 'NULL'
        if 'backup' in child:
            backup = f"&trace_{child['backup']['define_name']}"
        result['init_str'] += f"\ttrace_{child['define_name']}.backup = {backup};\n"
    return result


with open('trace.yaml', 'r', encoding='utf-8') as f:
    content = f.read()
    root = yaml.load(content, yaml.SafeLoader)
    parse_group(root)

    all_result = gen_group(root, root)
    all_define_str = all_result['define_str']
    all_init_str = all_result['init_str']
    all_probe_str = all_result['probe_str']
    all_index_str = all_result['index_str']

    if len(sys.argv) > 1 and sys.argv[1] == 'probe':
        print(f'''{all_index_str}
#define TRACE_MAX {global_status['trace_index']}
#define DEFINE_ALL_PROBES(FN, FN_tp, FNC)\t\t\\
{all_probe_str}
''')
    else:
        print(f'''#include "trace.h"
#include "progs/kprobe_trace.h"
#include "analysis.h"

{all_define_str}

trace_t *all_traces[TRACE_MAX];
int trace_count = TRACE_MAX;
LIST_HEAD(trace_list);

void init_trace_group()
{{
{all_init_str}
}}
''')
