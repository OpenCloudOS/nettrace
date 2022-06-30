#!/bin/python3
""" script that generate trace group info """
import subprocess
import sys
import yaml


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
            names = child['name'].split(':')
            if len(names) > 1:
                child['name'] = names[0]
                child['skb'] = names[1]
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


global_status = {}
global_names = {}
global_status['trace_index'] = 0

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

def gen_name(name, is_trace=False):
    if is_trace:
        name = name.replace('-', '_')
    else:
        name = f'__group_{name}'.replace('-', '_')
    if name in global_names:
        global_names[name] += 1
        return f'{name}_{global_names[name]}'
    global_names[name] = 0
    return name


def gen_group(group, is_root=False):
    if 'children' not in group:
        return

    define_str = ''
    init_str = ''
    probe_str = ''
    index_str = ''

    if is_root:
        p_name = 'root_group'
        group['define_name'] = p_name
        define_str += gen_group_init(group, p_name)
    else:
        p_name = group['define_name']

    for child in group['children']:
        if 'children' in child:
            name = gen_name(child["name"])
            child['define_name'] = name
            define_str += gen_group_init(child, name)
            init_str += f'\tlist_add_tail(&{name}.list, &{p_name}.children);\n'
            (_define_str, _init_str, _probe_str, _index_str) = gen_group(child)
            define_str += _define_str
            init_str += _init_str
            probe_str += _probe_str
            index_str += _index_str
        else:
            name = gen_name(child["name"], True)
            child['define_name'] = name
            skb_str = ''
            index_str += f'#define INDEX_{name} {global_status["trace_index"]}\n'
            if 'tp' in child:
                trace_type = 'TRACE_TP'
                tp = child['tp'].split(':')
                skb_str = f'\n\t.tp = "{child["tp"]}",'
                if 'skb' in child:
                    probe_str += f'\tFN_tp({name}, {tp[0]}, {tp[1]}, 8)\t\\\n'
            else:
                trace_type = 'TRACE_FUNCTION'
                if 'skb' in child:
                    skb_str = f'\n\t.skb = {child["skb"]},'
                    probe_str += f'\tFN({name}, {int(child["skb"]) + 1})\t\\\n'
            if 'analyzer' in child:
                analyzer = f'\n\t.analyzer = &ANALYZER({child["analyzer"]}),'
            else:
                analyzer = ''
            rule_str = ''
            if 'rules' in child:
                rules = child['rules']
                for index,rule in enumerate(rules):
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

            if_str = f'\n\t.if_str = "{child.get("if")}",' if 'if' in child else ''
            reg_str = f'\n\t.regex = "{child["regex"]}",' if 'regex' in child else ''
            msg_str = f'\n\t.msg = "{child["msg"]}",' if 'msg' in child else ''
            default = True
            if 'default' in child:
                default = child['default']
            elif 'default' in group:
                default = group['default']
            default = 'true' if default else 'false'
            default = f'\n\t.def = {default},'
            target = child.get('target') or child['name']
            define_str += f'''trace_t {name} = {{
\t.name = "{target}",
\t.desc = "{child.get('desc')}",{skb_str}{if_str}{default}
\t.type = {trace_type},{reg_str}{analyzer}{msg_str}
\t.index = INDEX_{name},
\t.prog = "__trace_{name}",
\t.parent = &{p_name},
\t.rules =  LIST_HEAD_INIT({name}.rules),
}};
{rule_str}
'''
            init_str += f'''\tlist_add_tail(&{name}.list, &{p_name}.traces);
\tall_traces[INDEX_{name}] = &{name};
\tlist_add_tail(&{name}.sibling, &trace_list);
'''
            global_status['trace_index'] += 1

    return (define_str, init_str, probe_str, index_str)


with open('trace.yaml', 'r', encoding='utf-8') as f:
    content = f.read()
    root = yaml.load(content, yaml.SafeLoader)
    parse_group(root)
    (all_define_str, all_init_str, all_probe_str, all_index_str) = gen_group(root, root)

    if len(sys.argv) > 1 and sys.argv[1] == 'probe':
        print(f'''{all_index_str}
#define TRACE_MAX {global_status['trace_index']}
#define _DEFINE_PROBE(FN, FN_tp)\t\t\\
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
