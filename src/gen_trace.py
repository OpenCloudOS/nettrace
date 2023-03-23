#!/bin/python3
""" script that generate trace group info """
import sys
import yaml

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
    names = trace['names']
    first = names[0]
    prev = None
    if isinstance(first, str):
        trace['name'] = first
    else:
        trace['name'] = first['name']
        if 'cond' in first:
            trace['cond'] = first['cond'].replace('"', '\\"')

    del trace['names']
    prev = trace

    for index in range(1, len(names)):
        name = names[index]
        new_child = dict(trace)

        if isinstance(name, str):
            new_child['name'] = name
            del new_child['cond']
        else:
            new_child['name'] = name['name']
            if 'cond' in name:
                new_child['cond'] = name['cond'].replace('"', '\\"')
            elif 'cond' in new_child:
                del new_child['cond']

        prev['next'] = new_child
        prev = new_child
        children.append(new_child)

    prev['next'] = trace


def parse_group(group):
    """ parse group in yaml file """
    if 'children' not in group:
        return
    children = group['children']
    i = 0
    while i < len(children):
        child = children[i]
        if not isinstance(child, str):
            parse_group(child)
            i += 1
            if 'names' in child:
                parse_names(child, children)
            name_split = child['name'].split(':')
            if len(name_split) > 1:
                child['name'] = name_split[0]
                child['skb'] = name_split[1]
            continue
        children.remove(child)
        data = child.split(':')
        if len(data) <= 1:
            child = {
                "name": data[0]
            }
        else:
            child = {
                "name": data[0],
                "skb": int(data[1])
            }
        children.insert(i, child)
        i += 1


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


def gen_trace(trace, group, p_name):
    name = gen_name(trace["name"], True)
    trace_name = 'trace_' + name
    trace['define_name'] = name
    probe_str = ''
    skb_str = ''
    index_str = f'#define INDEX_{name} {global_status["trace_index"]}\n'
    rule_str = ''
    init_str = ''

    if 'tp' in trace:
        trace_type = 'TRACE_TP'
        tp = trace['tp'].split(':')
        skb_str = f'\n\t.tp = "{trace["tp"]}",'
        if 'skb' in trace:
            probe_str = f'\tFN_tp({name}, {tp[0]}, {tp[1]}, {trace["skb"]})\t\\\n'
    else:
        trace_type = 'TRACE_FUNCTION'
        if 'skb' in trace:
            skb_index = int(trace["skb"]) + 1
            skb_str = f'\n\t.skb = {skb_index},'
            probe_str = f'\tFN({name}, {skb_index})\t\\\n'
        else:
            probe_str = f'\tFNC({name})\t\\\n'
    if 'analyzer' in trace:
        analyzer = f'\n\t.analyzer = &ANALYZER({trace["analyzer"]}),'
    else:
        analyzer = ''

    if 'rules' in trace:
        rules = trace['rules']
        (rule_str, _init_str) = gen_rules(rules, trace_name)
        init_str += _init_str

    cond_str = f'\n\t.cond = "{trace["cond"]}",' if 'cond' in trace else ''
    reg_str = f'\n\t.regex = "{trace["regex"]}",' if 'regex' in trace else ''
    msg_str = f'\n\t.msg = "{trace["msg"]}",' if 'msg' in trace else ''
    default = True
    if 'default' in trace:
        default = trace['default']
    elif 'default' in group:
        default = group['default']
    default = 'true' if default else 'false'
    default = f'\n\t.def = {default},'
    target = trace.get('target') or trace['name']
    define_str = f'''trace_t {trace_name} = {{
\t.name = "{target}",
\t.desc = "{trace.get('desc') or ''}",{skb_str}{cond_str}{default}
\t.type = {trace_type},{reg_str}{analyzer}{msg_str}
\t.index = INDEX_{name},
\t.prog = "__trace_{name}",
\t.parent = &{p_name},
\t.rules =  LIST_HEAD_INIT({trace_name}.rules),
\t.mutex = {'true' if trace.get('mutex') else 'false'},
}};
{rule_str}
'''
    init_str += f'''\tlist_add_tail(&{trace_name}.list, &{p_name}.traces);
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
        sibling = 'NULL'
        if 'next' in child:
            sibling = f"&trace_{child['next']['define_name']}"
        result['init_str'] += f"\ttrace_{child['define_name']}.sibling = {sibling};\n"
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
