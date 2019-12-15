import plotly.graph_objects as go

values = [['Herd', 'Probabilistic reporting', 'Probabilistic sampling', 'Strawman'], #1st col
  ['L * #flows * s', 'L * #flows', '0', 'L * #flows']]


fig = go.Figure(data=[go.Table(
  columnorder = [1,2],
  columnwidth = [80,400],
  header = dict(
    values = [['Technique'],
                  ['States required']],
    line_color='darkslategray',
    fill_color='royalblue',
    align=['left','center'],
    font=dict(color='white', size=12),
    height=40
  ),
  cells=dict(
    values=values,
    line_color='darkslategray',
    fill=dict(color=['paleturquoise', 'white']),
    align=['left', 'center'],
    font_size=12,
    height=30)
    )
])
fig.show()
